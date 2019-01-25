/*
**
** Copyright 2019, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

package android.security.identity_credential;

import javacard.framework.JCSystem;

public class DataRequestStore extends ExtendedCBORBuffer {

    private static final byte NAMESPACE_ELEMENTS_TOTAL = STATUS_WORDS;
    private static final byte NAMESPACE_ELEMENTS_READ = NAMESPACE_ELEMENTS_TOTAL + 1;

    public DataRequestStore(short ramSize, short flashSize, CBORDecoder cborDecoder) {
        super(JCSystem.makeTransientByteArray(ramSize, JCSystem.CLEAR_ON_DESELECT), new byte[flashSize], (byte) 2,
                cborDecoder);
    }

    /**
     * Check if the given name can be found in the currently loaded namespace. Note
     * that checks have to be done in the same order as they have been sent in the
     * data request by the reader (reader authentication data).
     * 
     * @param name       Buffer to the name that is queried
     * @param nameOffset Offset of the name
     * @param nameLen    Length of the name
     * @return Boolean indicating if the name was found or not.
     */
    public boolean isNameInNamespace(byte[] name, short nameOffset, short nameLen) {
        boolean foundName = false;

        initDecoder();

        while (!foundName && mStatusWords[NAMESPACE_ELEMENTS_READ] != mStatusWords[NAMESPACE_ELEMENTS_TOTAL]) {
            if (matchesString(name, nameOffset, nameLen, (short) -1)) {
                foundName = true;
            }
            mStatusWords[NAMESPACE_ELEMENTS_READ]++;
        }
        return foundName;
    }

    /**
     * Check if the given namespace can be found in the data request. If it is
     * found, sets the internal buffer pointer to the location of this namespace for
     * subsequent calls to {@link #isNameInNamespace}.
     * 
     * @param namespace       Buffer of the namespace name that should be loaded
     * @param namespaceOffset Offset to the namespace name
     * @param namespaceLen    Length of the namespace name
     * @return Boolean indicating if the namespace was found or not.
     */
    public boolean loadNamespaceConfig(byte[] namespace, short namespaceOffset, short namespaceLen) {        
        boolean foundNamespace = false;

        initDecoder();

        // Skip remaining names in namespace
        while (mStatusWords[NAMESPACE_ELEMENTS_TOTAL] != mStatusWords[NAMESPACE_ELEMENTS_READ]) {
            isNameInNamespace(mRamMemory, (short) 0, (short) 0);
        }

        while (!foundNamespace && mStatusWords[RAM_READ_POS] <= mStatusWords[RAM_WRITE_POS]) {
            if (matchesString(namespace, namespaceOffset, namespaceLen, (short) -1)) {
                foundNamespace = true;
                mStatusWords[NAMESPACE_ELEMENTS_TOTAL] = readLength(CBORBase.TYPE_ARRAY);
                mStatusWords[NAMESPACE_ELEMENTS_READ] = 0;
            } else {
                skipEntry(); // Skip the namespace configuration
            }
        }
        return foundNamespace;
    }
}
