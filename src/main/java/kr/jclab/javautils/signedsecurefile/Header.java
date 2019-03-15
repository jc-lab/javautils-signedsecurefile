/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package kr.jclab.javautils.signedsecurefile;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

class Header {
    private final Provider cipherProvider;

    public static final byte[] DATA_IV = {(byte)0x92, (byte)0xe5, (byte)0x26, (byte)0x21, (byte)0x1e, (byte)0xda, (byte)0xca, (byte)0x0f, (byte)0x89, (byte)0x5f, (byte)0x2b, (byte)0x74, (byte)0xc1, (byte)0xc4, (byte)0xb4, (byte)0xb9};

    private static final int COMMON_HEADER_SIZE = 32;
    private static final int SECURE_HEADER_SIZE = 84;
    public static final int VERSION = 2;
    private static final byte[] SIGNATURE = {(byte)0x0a, (byte)0x9b, (byte)0xd8, (byte)0x13, (byte)0x97, (byte)0x1f, (byte)0x93, (byte)0xe8, (byte)0x6b, (byte)0x7e, (byte)0xdf, (byte)0x05, (byte)0x70, (byte)0x54, (byte)0x02};

    public byte[] signature = Arrays.copyOf(SIGNATURE, SIGNATURE.length); // 15 bytes
    public byte version = VERSION; // 1 byte

    public HeaderCipherAlgorithm headerCipherAlgorithm = HeaderCipherAlgorithm.RSA;
    public DataCipherAlgorithm dataCipherAlgorithm = DataCipherAlgorithm.AES_CBC;
    public short signedSecureHeaderSize;
    public int keySize; // 4 bytes
    public byte[] rev1; // 8 bytes

    public final SecureHeader secureHeader = new SecureHeader();

    private byte[] signedSecureHeaderPrefix = null;
    private Cipher headerCipher = null;

    public Header(Provider cipherProvider) {
        this.cipherProvider = cipherProvider;
    }

    private Cipher createHeaderCipherWithSharedKey(byte[] sharedSecret, int mode) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, java.security.InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", this.cipherProvider);
        SecretKey headerKey = new SecretKeySpec(sharedSecret, "AES");
        cipher.init(mode, headerKey, new IvParameterSpec(DATA_IV));
        return cipher;
    }

    public void initEncrypt(Key asymmetricKey) throws IOException {
        try {
            if(headerCipherAlgorithm == HeaderCipherAlgorithm.EC)
            {
                ECKey ecKey = (ECKey)asymmetricKey;
                this.keySize = ecKey.getParams().getOrder().bitLength();

                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", this.cipherProvider);
                kpg.initialize(this.keySize);
                KeyPair kp = kpg.generateKeyPair();

                KeyAgreement ka = KeyAgreement.getInstance("ECDH");
                ka.init(asymmetricKey);
                ka.doPhase(kp.getPublic(), true);

                this.headerCipher = createHeaderCipherWithSharedKey(ka.generateSecret(), Cipher.ENCRYPT_MODE);

                byte[] encodedKey = kp.getPrivate().getEncoded();
                this.signedSecureHeaderPrefix = new byte[encodedKey.length + 2];

                this.signedSecureHeaderPrefix[0] = (byte)((encodedKey.length >> 0) & 0xFF);
                this.signedSecureHeaderPrefix[1] = (byte)((encodedKey.length >> 8) & 0xFF);
                System.arraycopy(encodedKey, 0, this.signedSecureHeaderPrefix, 2, encodedKey.length);
            }else{
                if(asymmetricKey instanceof RSAKey) {
                    RSAKey rsaKey = (RSAKey)asymmetricKey;
                    this.keySize = rsaKey.getModulus().bitLength();
                }else{
                    throw new IOException("Unknown key");
                }

                headerCipher = Cipher.getInstance(headerCipherAlgorithm.getCipherName(), this.cipherProvider);
                headerCipher.init(Cipher.ENCRYPT_MODE, asymmetricKey);
            }
        } catch (NoSuchAlgorithmException | java.security.InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException e) {
            throw new IOException("Invalid internal error");
        }
    }

    public byte[] decryptSignedSecureHeader(Key asymmetricKey, byte[] buffer) throws NoSuchPaddingException, NoSuchAlgorithmException, java.security.InvalidKeyException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        byte[] decodedSecureHeader = null;
        if(this.headerCipherAlgorithm == HeaderCipherAlgorithm.EC)
        {
            short encodedKeySize = (short)(
                            ((((short)buffer[0]) & 0xFF) << 0) |
                            ((((short)buffer[1]) & 0xFF) << 8)
                    );
            byte[] encodedKeyBytes = new byte[encodedKeySize];
            System.arraycopy(buffer, 2, encodedKeyBytes, 0, encodedKeySize);
            KeyFactory kf = KeyFactory.getInstance("EC", this.cipherProvider);
            PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(encodedKeyBytes));
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(privateKey);
            ka.doPhase(asymmetricKey, true);
            this.headerCipher = createHeaderCipherWithSharedKey(ka.generateSecret(), Cipher.DECRYPT_MODE);
            decodedSecureHeader = this.headerCipher.doFinal(buffer, 2 + encodedKeySize, buffer.length - 2 - encodedKeySize);
        }else{
            Cipher headerCipher = Cipher.getInstance(this.headerCipherAlgorithm.getCipherName(), this.cipherProvider);
            if(asymmetricKey instanceof PublicKey) {
                headerCipher.init(Cipher.DECRYPT_MODE, (PublicKey)asymmetricKey);
                decodedSecureHeader = headerCipher.doFinal(buffer);
            }else if(asymmetricKey instanceof PrivateKey) {
                headerCipher.init(Cipher.DECRYPT_MODE, (PrivateKey)asymmetricKey);
                decodedSecureHeader = headerCipher.doFinal(buffer);
            }else{
                throw new InvalidKeyException();
            }
        }
        return decodedSecureHeader;
    }

    public void readHeader(InputStream inputStream, Key asymmetricKey) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] buffer;
        if(inputStream.available() < COMMON_HEADER_SIZE)
            throw new InvalidFileException();
        buffer = new byte[COMMON_HEADER_SIZE];
        inputStream.read(buffer);
        this.signature = Arrays.copyOfRange(buffer, 0, SIGNATURE.length);
        this.version = buffer[15];

        if(!Arrays.equals(SIGNATURE, this.signature))
            throw new InvalidFileException();

        this.headerCipherAlgorithm = HeaderCipherAlgorithm.NONE;
        for (HeaderCipherAlgorithm value : HeaderCipherAlgorithm.values()) {
            if(value.getValue() == buffer[16])
            {
                this.headerCipherAlgorithm = value;
            }
        }
        if(this.headerCipherAlgorithm == HeaderCipherAlgorithm.NONE) {
            throw new InvalidFileException();
        }
        if(this.version > VERSION)
            throw new InvalidFileException("Version mismatch");
        this.dataCipherAlgorithm = DataCipherAlgorithm.NONE;
        for (DataCipherAlgorithm value : DataCipherAlgorithm.values()) {
            if(value.getValue() == buffer[17])
            {
                this.dataCipherAlgorithm = value;
            }
        }
        if(this.dataCipherAlgorithm == DataCipherAlgorithm.NONE) {
            throw new InvalidFileException();
        }
        this.signedSecureHeaderSize = (short)(
                        ((((short)buffer[18])& 0xFF) << 0) |
                        ((((short)buffer[19])& 0xFF) << 8)
                );
        this.keySize = ((((int)buffer[20]) & 0xFF) << 0) |
                        ((((int)buffer[21]) & 0xFF) << 8) |
                        ((((int)buffer[22]) & 0xFF) << 16) |
                        ((((int)buffer[23]) & 0xFF) << 24);
        this.rev1 = Arrays.copyOfRange(buffer, 20, 32);
        if(this.signedSecureHeaderSize <= 0)
            throw new InvalidFileException();
        if(inputStream.available() < this.signedSecureHeaderSize)
            throw new InvalidFileException();

        buffer = new byte[this.signedSecureHeaderSize];
        inputStream.read(buffer);

        try {
            this.secureHeader.readHeader(decryptSignedSecureHeader(asymmetricKey, buffer));
        } catch (NoSuchAlgorithmException e) {
            throw new NoSuchAlgorithmException();
        } catch (NoSuchPaddingException e) {
            throw new NoSuchAlgorithmException();
        } catch (java.security.InvalidKeyException e) {
            throw new InvalidKeyException();
        } catch (BadPaddingException e) {
            e.printStackTrace();;
            throw new InvalidFileException();
        } catch (IllegalBlockSizeException e) {
            throw new NoSuchAlgorithmException();
        } catch (InvalidKeySpecException e) {
            throw new NoSuchAlgorithmException();
        } catch (InvalidAlgorithmParameterException e) {
            throw new NoSuchAlgorithmException();
        }
    }

    public void writeHeader(OutputStream outputStream) throws IOException {
        byte[] signedSecureHeader = null;
        byte[] encHeader;
        try {
            encHeader = headerCipher.doFinal(secureHeader.makePayload());
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new IOException(e.getMessage());
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new IOException("Invalid internal error");
        }

        if(this.signedSecureHeaderPrefix != null) {
            signedSecureHeader = new byte[signedSecureHeaderPrefix.length + encHeader.length];
            System.arraycopy(this.signedSecureHeaderPrefix, 0, signedSecureHeader, 0, signedSecureHeaderPrefix.length);
            System.arraycopy(encHeader, 0, signedSecureHeader, signedSecureHeaderPrefix.length, encHeader.length);
        }else{
            signedSecureHeader = encHeader;
        }

        byte[] headerBuffer = new byte[COMMON_HEADER_SIZE];
        this.signedSecureHeaderSize = (short)signedSecureHeader.length;

        System.arraycopy(this.signature, 0, headerBuffer, 0, this.signature.length);
        headerBuffer[15] = this.version;
        headerBuffer[16] = this.headerCipherAlgorithm.getValue();
        headerBuffer[17] = this.dataCipherAlgorithm.getValue();
        headerBuffer[18] = ((byte)((this.signedSecureHeaderSize >> 0) & 0xFF));
        headerBuffer[19] = ((byte)((this.signedSecureHeaderSize >> 8) & 0xFF));
        headerBuffer[20] = ((byte)((this.keySize >> 0) & 0xFF));
        headerBuffer[21] = ((byte)((this.keySize >> 8) & 0xFF));
        headerBuffer[22] = ((byte)((this.keySize >> 16) & 0xFF));
        headerBuffer[23] = ((byte)((this.keySize >> 24) & 0xFF));
        outputStream.write(headerBuffer);
        outputStream.write(signedSecureHeader);
    }

    private boolean checkSignatureMatch(byte[] target, boolean includeVersion) {
        int i;
        for(i=0; i<15; i++) {
            if(target[i] != SIGNATURE[i])
                return false;
        }
        if(includeVersion && target[i] != VERSION)
            return false;
        return true;
    }

    public class SecureHeader {
        public byte[] sig; // 16
        public byte[] key; // 32
        public byte[] hmac; // 32
        public int datasize;

        public byte[] generateKey() {
            SecureRandom random = new SecureRandom();
            this.key = new byte[32];
            random.nextBytes(this.key);
            return this.key;
        }

        public void setting(byte[] hmac, int datasize) {
            this.sig = new byte[16];
            System.arraycopy(SIGNATURE, 0, this.sig, 0, SIGNATURE.length);
            this.sig[15] = VERSION;
            this.hmac = hmac;
            this.datasize = datasize;
        }

        public void readHeader(byte[] buffer) throws InvalidFileException {
            this.sig = Arrays.copyOfRange(buffer, 0, 16);
            this.key = Arrays.copyOfRange(buffer, 16, 48);
            this.hmac = Arrays.copyOfRange(buffer, 48, 80);
            this.datasize = ((((int)buffer[80]) & 0xFF) << 0) |
                    ((((int)buffer[81]) & 0xFF) << 8) |
                    ((((int)buffer[82]) & 0xFF) << 16) |
                    ((((int)buffer[83]) & 0xFF) << 24);
            if(!checkSignatureMatch(this.sig, true))
                throw new InvalidFileException();
        }

        public byte[] makePayload() {
            byte[] secureHeaderBuffer = new byte[SECURE_HEADER_SIZE];
            System.arraycopy(this.sig, 0, secureHeaderBuffer, 0, this.sig.length);
            System.arraycopy(this.key, 0, secureHeaderBuffer, 16, this.key.length);
            System.arraycopy(this.hmac, 0, secureHeaderBuffer, 48, this.hmac.length);
            secureHeaderBuffer[80] = ((byte)((this.datasize >> 0) & 0xFF));
            secureHeaderBuffer[81] = ((byte)((this.datasize >> 8) & 0xFF));
            secureHeaderBuffer[82] = ((byte)((this.datasize >> 16) & 0xFF));
            secureHeaderBuffer[83] = ((byte)((this.datasize >> 24) & 0xFF));
            return secureHeaderBuffer;
        }

        public boolean equalsHmac(byte[] target) {
            return Arrays.equals(this.hmac, target);
        }
    }
}
