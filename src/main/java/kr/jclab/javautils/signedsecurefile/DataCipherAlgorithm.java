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

public enum DataCipherAlgorithm {
    NONE((byte)0, null), AES_CBC((byte)1, "AES/CBC/PKCS5Padding");

    final private byte value;
    final private String algoName;

    DataCipherAlgorithm(byte value, String algoName) {
        this.value = value;
        this.algoName = algoName;
    }

    public final byte getValue() {
        return this.value;
    }

    public final String getAlgoName() {
        return this.algoName;
    }
}
