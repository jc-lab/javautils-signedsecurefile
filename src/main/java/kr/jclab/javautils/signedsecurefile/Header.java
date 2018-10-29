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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;
import java.util.Arrays;

class Header {
    public static final byte[] DATA_IV = {(byte)0x92, (byte)0xe5, (byte)0x26, (byte)0x21, (byte)0x1e, (byte)0xda, (byte)0xca, (byte)0x0f, (byte)0x89, (byte)0x5f, (byte)0x2b, (byte)0x74, (byte)0xc1, (byte)0xc4, (byte)0xb4, (byte)0xb9};

    private static final int COMMON_HEADER_SIZE = 32;
    private static final int SECURE_HEADER_SIZE = 84;
    public static final int VERSION = 1;
    private static final byte[] SIGNATURE = {(byte)0x0a, (byte)0x9b, (byte)0xd8, (byte)0x13, (byte)0x97, (byte)0x1f, (byte)0x93, (byte)0xe8, (byte)0x6b, (byte)0x7e, (byte)0xdf, (byte)0x05, (byte)0x70, (byte)0x54, (byte)0x02};

    public byte[] signature = Arrays.copyOf(SIGNATURE, SIGNATURE.length); // 15 bytes
    public byte version = VERSION; // 1 byte

    public HeaderCipherAlgorithm headerCipherAlgorithm = HeaderCipherAlgorithm.RSA;
    public DataCipherAlgorithm dataCipherAlgorithm = DataCipherAlgorithm.AES_CBC;
    // rev 2 bytes
    public int keySize; // 4 bytes
    public byte[] rev1; // 8 bytes

    public final SecureHeader secureHeader = new SecureHeader();

    public void readHeader(InputStream inputStream, Key asymmetricKey) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] buffer;
        int encBlockSize;
        if(inputStream.available() < COMMON_HEADER_SIZE)
            throw new InvalidFileException();
        buffer = new byte[COMMON_HEADER_SIZE];
        inputStream.read(buffer);
        this.signature = Arrays.copyOfRange(buffer, 0, SIGNATURE.length);
        this.version = buffer[15];

        if(!Arrays.equals(SIGNATURE, this.signature))
            throw new InvalidFileException();

        if(this.version != VERSION)
            throw new InvalidFileException("Version mismatch");

        this.headerCipherAlgorithm = HeaderCipherAlgorithm.NONE;
        for (HeaderCipherAlgorithm value : HeaderCipherAlgorithm.values()) {
            if(value.getValue() == buffer[16])
            {
                this.headerCipherAlgorithm = value;
            }
        }
        if(this.dataCipherAlgorithm == DataCipherAlgorithm.NONE) {
            throw new InvalidFileException();
        }
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
        this.keySize = ((((int)buffer[20]) & 0xFF) << 0) |
                        ((((int)buffer[21]) & 0xFF) << 8) |
                        ((((int)buffer[22]) & 0xFF) << 16) |
                        ((((int)buffer[23]) & 0xFF) << 24);
        this.rev1 = Arrays.copyOfRange(buffer, 20, 32);
        encBlockSize = this.keySize / 8;
        if(encBlockSize <= 0)
            throw new InvalidFileException();
        if(inputStream.available() < encBlockSize)
            throw new InvalidFileException();

        buffer = new byte[encBlockSize];
        inputStream.read(buffer);

        try {
            Cipher headerCipher = Cipher.getInstance(this.headerCipherAlgorithm.getAlgoName());
            if(asymmetricKey instanceof PublicKey) {
                headerCipher.init(Cipher.DECRYPT_MODE, (PublicKey)asymmetricKey);
                buffer = headerCipher.doFinal(buffer);
            }else if(asymmetricKey instanceof PrivateKey) {
                headerCipher.init(Cipher.DECRYPT_MODE, (PrivateKey)asymmetricKey);
                buffer = headerCipher.doFinal(buffer);
            }else{
                throw new InvalidKeyException();
            }
            this.secureHeader.readHeader(buffer);
        } catch (NoSuchAlgorithmException e) {
            throw e;
        } catch (NoSuchPaddingException e) {
            throw new NoSuchAlgorithmException();
        } catch (java.security.InvalidKeyException e) {
            throw new InvalidKeyException();
        } catch (BadPaddingException e) {
            throw new InvalidFileException();
        } catch (IllegalBlockSizeException e) {
            throw new NoSuchAlgorithmException();
        }
    }

    public void writeHeader(OutputStream outputStream, Cipher headerCipher) throws IOException {
        try {
            byte[] headerBuffer = new byte[COMMON_HEADER_SIZE];

            System.arraycopy(this.signature, 0, headerBuffer, 0, this.signature.length);
            headerBuffer[15] = this.version;
            headerBuffer[16] = this.headerCipherAlgorithm.getValue();
            headerBuffer[17] = this.dataCipherAlgorithm.getValue();
            headerBuffer[20] = ((byte)((this.keySize >> 0) & 0xFF));
            headerBuffer[21] = ((byte)((this.keySize >> 8) & 0xFF));
            headerBuffer[22] = ((byte)((this.keySize >> 16) & 0xFF));
            headerBuffer[23] = ((byte)((this.keySize >> 24) & 0xFF));
            outputStream.write(headerBuffer);
            outputStream.write(headerCipher.doFinal(secureHeader.makePayload()));
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            throw new IOException("Invalid internal error");
        }
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
