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

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RandomData;

public class CryptoManager {

    // Hardware bound key, initialized during Applet installation 
    private AESKey mHBK;

    private KeyPair mECKeyPair;
    
    // Random number generator for IV usage (TODO: implement my own counter based IV generator)
    // Secure random number generator
    private RandomData mRandom;

    private byte[] mTempBuffer;

    private APDUManager mAPDUManager;
    
    private CBORDecoder mCBORDecoder;
    
    private CBOREncoder mCBOREncoder;
    
    public CryptoManager(APDUManager apduManager, CBORDecoder decoder, CBOREncoder encoder) {
        mTempBuffer = JCSystem.makeTransientByteArray((short)64, JCSystem.CLEAR_ON_DESELECT);
        mRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        mRandom.generateData(mTempBuffer, (short)0, (short)32);
        
        mHBK = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
        mHBK.setKey(mTempBuffer, (short)0);
        
        mECKeyPair = new KeyPair(
                (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false),
                (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false));
        
        // At the moment we only support SEC-P256r1. Hence, can be configured at install time.
        Secp256r1.configureECKeyParameters((ECKey) mECKeyPair.getPrivate());
        Secp256r1.configureECKeyParameters((ECKey) mECKeyPair.getPublic());
        
        mAPDUManager = apduManager;
        mCBORDecoder = decoder;
        mCBOREncoder = encoder;
    }

    public void reset() {
        // TODO Auto-generated method stub
        
    }
    
    public void process() {
        byte[] buf = mAPDUManager.getReceiveBuffer();
        switch(buf[ISO7816.OFFSET_INS]) {
        case ISO7816.INS_ICS_CREATE_EPHEMERAL_KEY:
            processCreateEphemeralKey();
            break;
        case ISO7816.INS_ICS_CREATE_CREDENTIAL:
            break;
        case ISO7816.INS_ICS_CREATE_SIGNING_KEY:
            break;
        default: 
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void processCreateEphemeralKey() {
        byte[] buf = mAPDUManager.getReceiveBuffer();
        
        switch (Util.getShort(buf, ISO7816.OFFSET_P1)) {
        case 0: // Do nothing
        case 1: // EC_NIST_P_256
            mECKeyPair.genKeyPair();
            
            mCBOREncoder.encodeArrayStart((short) 2);
            short length = ((ECPublicKey)mECKeyPair.getPublic()).getW(mTempBuffer, (short)0);
            mCBOREncoder.encodeByteString(mTempBuffer, (short) 0, length);
            
            length = ((ECPrivateKey)mECKeyPair.getPrivate()).getS(mTempBuffer, (short)0);
            mCBOREncoder.encodeByteString(mTempBuffer, (short) 0, length);
        default: 
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
            
        }
    }

    public void createCredentialBlobAndWrap(byte[] outCredentialBlob, short outOffset) {
        //TODO: implement
    }
    
    public void unwrapCredentialBlob(byte[] credentialBlob, short offset, short length) {
        //TODO: implement
    }
    
    public short createCredentialCertificate(byte[] outCertificateBuffer, short outOffset) {
        return 0;
    }
    
    public short encryptCredentialData(byte[] data, short offset, short length, byte[] outBuffer, short outOffset) {
        //TODO: implement
        return 0;
    }
    
    public short decryptCredentialData(byte[] encryptedData, short offset, short length, byte[] outData, short outOffset) {
        //TODO: implement
        return 0;
    }

    public void createSigningKeyAndWrap(byte[] outSigningBlob, short outOffset) {
        //TODO: implement
    }
    
    public void unwrapSigningBlob(byte[] signingBlob, short offset, short length) {
        //TODO: implement
    }
    
    public short createSigningKeyCertificate(byte[] outCertificateBuffer, short outOffset) {
        //TODO: implement
        return 0;
    }
    
    public short signData(byte[] data, short offset, short length, byte[] outSignature, short outOffset) {
        //TODO: implement
        return 0;
    }


}
