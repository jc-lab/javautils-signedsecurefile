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

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.validation.constraints.NotNull;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

public final class SignedSecureFileInputStream extends InputStream {
    private final Provider cipherProvider = new BouncyCastleProvider();
    private final String HMAC_SHA256_ALGORITHM = "HmacSHA256";

    private InputStream m_stream = null;
    private ByteBuffer m_dataBuffer = null;

    public SignedSecureFileInputStream(@NotNull InputStream inputStream, @NotNull Key asymmetricKey, String secretKey) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher dataCipher;
        SecretKey dataKey;
        Header header = new Header(cipherProvider);
        header.readHeader(inputStream, asymmetricKey);
        m_stream = inputStream;

        try {
            byte[] bytesDataKey;
            byte[] dataBuffer;
            int readLen;
            byte[] bytesHmac;
            byte[] decbuf;
            SecretKeySpec signingKey = new SecretKeySpec(secretKey.getBytes(), HMAC_SHA256_ALGORITHM);
            Mac mac = Mac.getInstance(HMAC_SHA256_ALGORITHM);
            mac.init(signingKey);
            bytesDataKey = mac.doFinal(header.secureHeader.key);
            dataKey = new SecretKeySpec(bytesDataKey, header.dataCipherAlgorithm.getAlgoName().split("/")[0]);
            dataCipher = Cipher.getInstance(header.dataCipherAlgorithm.getAlgoName());
            dataCipher.init(Cipher.DECRYPT_MODE, dataKey, new IvParameterSpec(Header.DATA_IV));

            mac.reset();
            m_dataBuffer = ByteBuffer.allocate(header.secureHeader.datasize);
            dataBuffer = new byte[1024];
            while((readLen = m_stream.read(dataBuffer)) > 0) {
                if((readLen % 16) > 0) {
                    throw new InvalidFileException("file broken");
                }
                decbuf = dataCipher.update(dataBuffer, 0, readLen);
                mac.update(decbuf);
                m_dataBuffer.put(decbuf);
            }
            decbuf = dataCipher.doFinal();
            mac.update(decbuf);
            m_dataBuffer.put(decbuf);
            m_dataBuffer.position(0);

            bytesHmac = mac.doFinal();
            if(!header.secureHeader.equalsHmac(bytesHmac)) {
                throw new InvalidKeyException();
            }
        } catch (BadPaddingException e) {
            throw new InvalidKeyException();
        } catch (java.security.InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException e) {
            throw new IOException("Invalid internal error");
        } catch (InvalidAlgorithmParameterException e) {
            throw new NoSuchAlgorithmException(e.getMessage());
        }
    }

    @Override
    public int read(byte[] b) throws IOException {
        int readlen;
        int remaining = m_dataBuffer.remaining();
        if(remaining <= 0)
            return -1;
        readlen = Math.min(remaining, b.length);
        m_dataBuffer.get(b, 0, readlen);
        return readlen;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        int readlen;
        int remaining = m_dataBuffer.remaining();
        if(remaining <= 0)
            return -1;
        readlen = Math.min(remaining, len);
        m_dataBuffer.get(b, off, readlen);
        return readlen;
    }

    @Override
    public long skip(long n) throws IOException {
        int remaining = m_dataBuffer.remaining();
        long skiplen = (n > remaining) ? remaining : n;
        long count = skiplen;
        while((count--) > 0)
            m_dataBuffer.get();
        return skiplen;
    }

    @Override
    public int available() throws IOException {
        return m_dataBuffer.remaining();
    }

    @Override
    public void close() throws IOException {
        if(m_stream != null) {
            m_stream.close();
            m_stream = null;
        }
    }

    @Override
    public synchronized void mark(int readlimit) {
    }

    @Override
    public synchronized void reset() throws IOException {
        m_dataBuffer.reset();
    }

    @Override
    public boolean markSupported() {
        return false;
    }

    @Override
    public int read() throws IOException {
        return m_dataBuffer.get();
    }
}
