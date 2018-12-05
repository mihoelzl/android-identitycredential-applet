/*
**
** Copyright 2018, The Android Open Source Project
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

package org.isodl.mdl;

import java.util.Random;

import com.nxp.id.jcopx.security.CipherX;
import com.nxp.id.jcopx.security.CryptoBaseX;

import javacard.framework.JCSystem;
import javacard.security.AESKey;
import javacard.security.ECKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

public class CryptoManager {

    // Hardware bound key, initialized during Applet installation 
    private AESKey mHBK;
    
    // Secure random number generator
    private static RandomData mRandom;

    // Random number generator for IV usage (TODO: implement my own counter based IV generator)
    private static RandomData mIVgenerator;

    private static byte[] mTempBuffer;
    
    public CryptoManager() {
        mTempBuffer = JCSystem.makeTransientByteArray((short)64, JCSystem.CLEAR_ON_DESELECT);
        mRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        mRandom.generateData(mTempBuffer, (short)0, (short)32);
        
        mHBK = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
        mHBK.setKey(mTempBuffer, (short)0);
    }


    public void createCredentialBlobAndWrap(byte[] outCredentialBlob, short outOffset) {
        //TODO: implement
    }

    public void unwrapCredentialBlob(byte[] credentialBlob, short offset, short length) {
        //TODO: implement
    }

}
