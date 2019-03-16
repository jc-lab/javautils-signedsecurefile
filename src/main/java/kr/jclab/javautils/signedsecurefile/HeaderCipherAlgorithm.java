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

public enum HeaderCipherAlgorithm {
    NONE((byte)0, null, null),
    V1_RSA((byte)1, "v1_RSA", "RSA"),
    EC((byte)2, "EC", null),
    RSA((byte)3, "RSA", "RSA/ECB/PKCS1Padding");

    final private byte value;
    final private String algoName;
    final private String cipherName;

    HeaderCipherAlgorithm(byte value, String algoName, String cipherName) {
        this.value = value;
        this.algoName = algoName;
        this.cipherName = cipherName;
    }

    public final byte getValue() {
        return this.value;
    }

    public final String getAlgoName() {
        return this.algoName;
    }

    public String getCipherName() {
        return cipherName;
    }

    public static HeaderCipherAlgorithm findByName(String name) {
        for(HeaderCipherAlgorithm item : values()) {
            if(name.equalsIgnoreCase(item.getAlgoName()))
                return item;
        }
        return null;
    }
}
