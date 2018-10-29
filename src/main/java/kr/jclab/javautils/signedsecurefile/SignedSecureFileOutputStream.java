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

import javax.validation.constraints.NotNull;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public final class SignedSecureFileOutputStream extends OutputStream {
    private final String HMAC_SHA256_ALGORITHM = "HmacSHA256";

    private Header m_header = null;
    private OutputStream m_stream = null;
    private boolean m_isSaved = false;
    private Cipher m_headerCipher = null;

    private Cipher m_dataCipher = null;
    private Mac m_dataHmac = null;
    private ByteArrayOutputStream m_encryptedDataBuffer = null;
    private int m_datasize = 0;

    public SignedSecureFileOutputStream(@NotNull OutputStream outputStream, @NotNull Key asymmetricKey, HeaderCipherAlgorithm headerCipherAlgorithm, String secretKey) throws IOException, InvalidKeyException {
        SecureRandom random = new SecureRandom();
        m_header = new Header();
        m_stream = outputStream;
        m_header.headerCipherAlgorithm = headerCipherAlgorithm;

        try {
            SecretKey dataKey;
            byte[] bytesDataKey;
            SecretKeySpec signingKey = new SecretKeySpec(secretKey.getBytes(), HMAC_SHA256_ALGORITHM);
            Mac mac = Mac.getInstance(HMAC_SHA256_ALGORITHM);
            mac.init(signingKey);
            m_dataHmac = mac;
            m_headerCipher = Cipher.getInstance(m_header.headerCipherAlgorithm.getAlgoName());
            m_headerCipher.init(Cipher.ENCRYPT_MODE, asymmetricKey);
            m_header.keySize = m_headerCipher.getOutputSize(1) * 8;
            bytesDataKey = mac.doFinal(m_header.secureHeader.generateKey());
            dataKey = new SecretKeySpec(bytesDataKey, m_header.dataCipherAlgorithm.getAlgoName().split("/")[0]);
            m_dataCipher = Cipher.getInstance(m_header.dataCipherAlgorithm.getAlgoName());
            m_dataCipher.init(Cipher.ENCRYPT_MODE, dataKey, new IvParameterSpec(Header.DATA_IV));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException e) {
            throw new IOException("Invalid interal error");
        } catch (java.security.InvalidKeyException e) {
            throw new InvalidKeyException();
        }

        m_encryptedDataBuffer = new ByteArrayOutputStream();
    }

    public void save() throws IOException, IllegalStateException {
        if(m_isSaved)
            throw new IllegalStateException();

        try {
            m_encryptedDataBuffer.write(m_dataCipher.doFinal());
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }

        m_header.secureHeader.setting(m_dataHmac.doFinal(), m_datasize);
        m_header.writeHeader(m_stream, m_headerCipher);
        m_encryptedDataBuffer.writeTo(m_stream);

        m_isSaved = true;
    }

    @Override
    public void write(byte[] b) throws IOException {
        m_dataHmac.update(b);
        m_encryptedDataBuffer.write(m_dataCipher.update(b));
        m_datasize += b.length;
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        byte[] encbuf = m_dataCipher.update(b, off, len);
        m_dataHmac.update(b, off, len);
        m_encryptedDataBuffer.write(encbuf);
        m_datasize += len;
    }

    @Override
    public void flush() throws IOException {
    }

    @Override
    public void close() throws IOException {
        if(!m_isSaved)
            save();
    }

    @Override
    public void write(int b) throws IOException {
        byte[] temp = new byte[] { (byte)b };
        m_encryptedDataBuffer.write(temp);
        m_encryptedDataBuffer.write(m_dataCipher.update(temp));
        m_datasize += 1;
    }
}
