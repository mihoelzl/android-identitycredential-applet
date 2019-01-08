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

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;

public class AccessControlManager {

    private static final byte STATUS_AUTHENTICATION = 0;
    private static final byte STATUS_LOADPROFILES = 1;
    private static final byte STATUS_GETENTRIES = 2;

    private static final byte VALUE_CURRENT_STATUS = 0;
    private static final byte VALUE_VALID_PROFILE_IDS = 1;
    private static final byte VALUE_READER_KEY_LENGTH = 2;
    private static final byte STATUS_WORDS = 3;

    private static final byte BUFFERPOS_USERID_LENGTH = 8;
    
    private static final short BUFFERPOS_READERKEY = 0;
    private static final short BUFFERPOS_USERID = BUFFERPOS_READERKEY + 65;
    private static final short BUFFERPOS_PROFILEIDS = BUFFERPOS_USERID + BUFFERPOS_USERID_LENGTH;
    private static final short TEMPBUFFER_SIZE = BUFFERPOS_PROFILEIDS + 128;

    private static final byte LENGTH_MAPKEY_READERAUTHPUBKEY = 16;
    
    private final short[] mStatusWords;
    
    private final byte[] mTempBuffer;

    private final CryptoManager mCryptoManager;
    
    private final APDUManager mAPDUManager;

    // Reference to the internal CBOR decoder instance
    private final CBORDecoder mCBORDecoder;
    
    // Reference to the internal CBOR encoder instance
    private final CBOREncoder mCBOREncoder;
    
    public AccessControlManager(CryptoManager cryptoManager, APDUManager apduManager, CBORDecoder decoder, CBOREncoder encoder) {
        mCryptoManager = cryptoManager;
        
        mAPDUManager = apduManager;
        
        mCBOREncoder = encoder;
        
        mCBORDecoder = decoder;
        
        mTempBuffer  = JCSystem.makeTransientByteArray(TEMPBUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
             
        mStatusWords = JCSystem.makeTransientShortArray(STATUS_WORDS, JCSystem.CLEAR_ON_DESELECT);
    }
    
    public void reset() {
        mStatusWords[VALUE_VALID_PROFILE_IDS] = 0;
        mStatusWords[VALUE_READER_KEY_LENGTH] = 0;
        setStatus(STATUS_AUTHENTICATION);
    }

    public void process() {
        byte[] buf = mAPDUManager.getReceiveBuffer();
        switch (buf[ISO7816.OFFSET_INS]) {
        case ISO7816.INS_ICS_AUTHENTICATE:
            processAuthenticate();
            break;
        case ISO7816.INS_ICS_LOAD_ACCESS_CONTROL_PROFILE:
            processLoadAccessControlProfile();
            break;
        default:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
    
    public void authenticationDone() {
        setStatus(STATUS_LOADPROFILES);
    }
    
    public void profilesLoaded() {
        setStatus(STATUS_GETENTRIES);
    }
    
    
    public void setStatus(byte status) {
        mStatusWords[VALUE_CURRENT_STATUS] = status;
    }
    
    private void addValidProfileId(byte pId) {
        mTempBuffer[(short)(BUFFERPOS_PROFILEIDS + mStatusWords[VALUE_VALID_PROFILE_IDS])] = pId;
        mStatusWords[VALUE_VALID_PROFILE_IDS]++;
    }
    
    public boolean authenticateReader(byte[] sessionTranscript, short offset, short length, byte[] readerKey,
            short readerKeyOffset, short readerKeyLength, byte[] rederSignature, short readerSignatureOffset,
            short readerSignatureLength) {
        
        // TODO parse reader public key and ephemeral key from session transcript
        // TODO verify the signature over transcript
        // mCryptoManager.verifyReaderSignature()
        
        // TODO verify that the ephemeral key has not changed
        // mCryptoManager.verifyEphemeralKey(holderPubKey, holderKeyOffset, holderKeyLength);

        mStatusWords[VALUE_READER_KEY_LENGTH] = readerKeyLength; 
        return true;
    }
    
    public boolean authenticateUser(byte[] authToken, short tokenOffset) {
        // TODO: How to we verify the token?
        
        Util.arrayCopyNonAtomic(authToken, tokenOffset, mTempBuffer, BUFFERPOS_USERID, BUFFERPOS_USERID_LENGTH);
        
        return true;
    }

    /**
     * Process the AUTHENTICATE command (validate encrypted access control profiles)
     */
    private void processAuthenticate() {
        short receivingLength = mAPDUManager.receiveAll();
        byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();
        short inOffset = mAPDUManager.getOffsetIncomingData();
        
        short p1p2 =Util.getShort(receiveBuffer, ISO7816.OFFSET_P1);
        
        mCBORDecoder.init(receiveBuffer, inOffset, receivingLength);
        short len = mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);
        if(p1p2 == 0x0) { // No authentication, just 
            authenticationDone();
        } else if(p1p2 == 0x1 && len == 2) { // Reader authentication
            short transcriptLen = mCBORDecoder.readMajorType(CBORBase.TYPE_BYTE_STRING);
            short transcriptOffset = mCBORDecoder.getCurrentOffsetAndIncrease(len);
            short readerAuthPubKeyLen= mCBORDecoder.readMajorType(CBORBase.TYPE_BYTE_STRING);
            short readerAuthPubKeyOffset = mCBORDecoder.getCurrentOffsetAndIncrease(len);
            short readerSignLen= mCBORDecoder.readMajorType(CBORBase.TYPE_BYTE_STRING);
            short readerSignOffset = mCBORDecoder.getCurrentOffsetAndIncrease(len);

            if (!authenticateReader(receiveBuffer, transcriptOffset, transcriptLen, receiveBuffer,
                    readerAuthPubKeyOffset, readerAuthPubKeyLen, receiveBuffer, readerSignOffset, readerSignLen)) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            authenticationDone();
        } else if (p1p2 == 0x2 && len == 1) { // User authentication
            len = mCBORDecoder.readMajorType(CBORBase.TYPE_BYTE_STRING);
            short tokenOffset = mCBORDecoder.getCurrentOffsetAndIncrease(len);

            if (!authenticateUser(receiveBuffer, tokenOffset)) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            authenticationDone();
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    public boolean processLoadAccessControlProfile() {
        short receivingLength = mAPDUManager.receiveAll();
        byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();
        short inOffset = mAPDUManager.getOffsetIncomingData();

        if (Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != 0x0) { 
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        
        mAPDUManager.setOutgoing();
        
        mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);

        // Start location of the profile
        short profileOffset = mCBORDecoder.getCurrentOffset();
        
        // Skip the actual access control profile (we will only encrypt it
        short profileLength = (short)(mCBORDecoder.skipEntry() - profileOffset);

        short tagOffset = mCBORDecoder.getCurrentOffset();
        
        try {
            mCryptoManager.verifyAuthenticationTag(receiveBuffer, profileOffset, profileLength, receiveBuffer, tagOffset);

            // Success: check if authentication is valid for this profile and store the id  
            mCBORDecoder.init(receiveBuffer, profileOffset, receivingLength);
            
            short mapSize = mCBORDecoder.readMajorType(CBORBase.TYPE_MAP);
            
            mCBORDecoder.readMajorType(CBORBase.TYPE_TEXT_STRING); // ignore actual keys, we assume a fixed structure
            byte pId = mCBORDecoder.readInt8();
            
            if (mapSize >= 2) {
                short keyLength = mCBORDecoder.readMajorType(CBORBase.TYPE_TEXT_STRING);
                mCBORDecoder.increaseOffset(keyLength);
                
                if(keyLength == LENGTH_MAPKEY_READERAUTHPUBKEY) { // No exact match check needed
                    // reader authentication, check if public key matches the authenticated pub key
                    // TODO: Handle public key certificate chain 
                    short readerKeyLength = mCBORDecoder.readMajorType(CBORBase.TYPE_BYTE_STRING);
                    if (Util.arrayCompare(mTempBuffer, BUFFERPOS_READERKEY, receiveBuffer,
                            mCBORDecoder.getCurrentOffsetAndIncrease(readerKeyLength), readerKeyLength) != 0) {
                        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                    }
                }
                
                if(mCBORDecoder.getCurrentOffset() != receivingLength) { // user authentication 
                    // userAuthType
                    keyLength = mCBORDecoder.readMajorType(CBORBase.TYPE_TEXT_STRING);
                    mCBORDecoder.increaseOffset(keyLength);

                    short type = mCBORDecoder.readMajorType(CBORBase.TYPE_UNSIGNED_INTEGER);
                    
                    // userSecureId
                    keyLength = mCBORDecoder.readMajorType(CBORBase.TYPE_TEXT_STRING);
                    mCBORDecoder.increaseOffset(keyLength);
                    if (Util.arrayCompare(mTempBuffer, BUFFERPOS_USERID, receiveBuffer,
                            mCBORDecoder.getCurrentOffsetAndIncrease(BUFFERPOS_USERID_LENGTH), BUFFERPOS_USERID_LENGTH) != 0) {
                        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                    }
                    
                    // TODO: check timeout + type
                }
            } 
            // All authentications validated (or no authentication was required for this profile)
            addValidProfileId(pId);
            
        } catch (CryptoException e) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        
        return true;
    }
}
