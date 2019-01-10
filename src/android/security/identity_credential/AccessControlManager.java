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

    private static final byte STATUS_TRANSCRIPT_LOADED = 0;
    private static final byte STATUS_READER_AUTHENTICATED= 1;
    private static final byte STATUS_USER_AUTHENTICATED = 2;

    private static final byte VALUE_CURRENT_STATUS = 0;
    private static final byte VALUE_VALID_PROFILE_IDS = 1;
    private static final byte VALUE_READER_KEY_LENGTH = 2;
    private static final byte STATUS_WORDS = 3;

    private static final byte MAX_USER_ID_LENGTH = 8;
    private static final byte MAX_PROFILE_IDS = 127;
    
    private static final short BUFFERPOS_READERKEY = 0;
    private static final short BUFFERPOS_USERID = BUFFERPOS_READERKEY + 65;
    private static final short BUFFERPOS_PROFILEIDS = BUFFERPOS_USERID + MAX_USER_ID_LENGTH;
    private static final short TEMPBUFFER_SIZE = BUFFERPOS_PROFILEIDS + MAX_PROFILE_IDS;

    private static final byte LENGTH_MAPKEY_READERAUTHPUBKEY = 16;
    
    private final short[] mStatusWords;
    
    private final byte[] mTempBuffer;
    
    private final APDUManager mAPDUManager;

    // Reference to the internal CBOR decoder instance
    private final CBORDecoder mCBORDecoder;
        
    public AccessControlManager(APDUManager apduManager, CBORDecoder decoder) {        
        mAPDUManager = apduManager;
                
        mCBORDecoder = decoder;
        
        mTempBuffer  = JCSystem.makeTransientByteArray(TEMPBUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
             
        mStatusWords = JCSystem.makeTransientShortArray(STATUS_WORDS, JCSystem.CLEAR_ON_DESELECT);
    }
    
    public void reset() {
        mStatusWords[VALUE_VALID_PROFILE_IDS] = 0;
        mStatusWords[VALUE_READER_KEY_LENGTH] = 0;
        mStatusWords[VALUE_CURRENT_STATUS] = 0;
    }

    public void process(CryptoManager cryptoManager) {
        byte[] buf = mAPDUManager.getReceiveBuffer();
        switch (buf[ISO7816.OFFSET_INS]) {
        case ISO7816.INS_ICS_AUTHENTICATE:
            processAuthenticate(cryptoManager);
            break;
        case ISO7816.INS_ICS_LOAD_ACCESS_CONTROL_PROFILE:
            processLoadAccessControlProfile(cryptoManager);
            break;
        default:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
    
    /**
     * Sets the status of the access control profile manager
     */
    private void setStatusFlag(byte statusFlag) {
        mStatusWords[VALUE_CURRENT_STATUS] = ICUtil.setBit((byte) mStatusWords[VALUE_CURRENT_STATUS], statusFlag, true);
    }

    /** 
     * Get the current status of the manager 
     */
    private boolean getStatusFlag(byte statusFlag) {
        return ICUtil.getBit((byte) mStatusWords[VALUE_CURRENT_STATUS], statusFlag);
    }
    
    
    /**
     * Add access control profile id to the verified id list. Access to entries that
     * reference one of these ids will be granted.
     * 
     * @param pId New access control profile id
     */
    private void addValidProfileId(byte pId) {
        if(mStatusWords[VALUE_VALID_PROFILE_IDS] >= MAX_PROFILE_IDS) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
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

        
        return true;
    }
    
    public boolean authenticateUser(byte[] authToken, short tokenOffset, short tokenLength) {
        // TODO: How to we verify the token?
        
        Util.arrayCopyNonAtomic(authToken, tokenOffset, mTempBuffer, BUFFERPOS_USERID, tokenLength);
        
        return true;
    }

    /**
     * Process the AUTHENTICATE command (validate encrypted access control profiles)
     * 
     * @param cryptoManager Reference to the cryptomanager that will get the session
     *                      transcript if it is provided
     */
    private void processAuthenticate(CryptoManager cryptoManager) {
        short receivingLength = mAPDUManager.receiveAll();
        byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();
        short inOffset = mAPDUManager.getOffsetIncomingData();
        
        short p1p2 =Util.getShort(receiveBuffer, ISO7816.OFFSET_P1);
        
        mCBORDecoder.init(receiveBuffer, inOffset, receivingLength);
        short len = mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);
        if (p1p2 == 0x0) { // No authentication, just the session transcript
            if (getStatusFlag(STATUS_TRANSCRIPT_LOADED)) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED); // Already loaded
            }
            len = mCBORDecoder.readMajorType(CBORBase.TYPE_BYTE_STRING);
            cryptoManager.startRetrievalSignature(receiveBuffer, mCBORDecoder.getCurrentOffsetAndIncrease(len), len);
            setStatusFlag(STATUS_TRANSCRIPT_LOADED);
        } else if (p1p2 == 0x1) { // Reader authentication
            if (getStatusFlag(STATUS_READER_AUTHENTICATED)) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED); // Already authenticated
            }
            short transcriptLen = mCBORDecoder.readMajorType(CBORBase.TYPE_BYTE_STRING);
            short transcriptOffset = mCBORDecoder.getCurrentOffsetAndIncrease(transcriptLen);
            short readerAuthPubKeyLen = mCBORDecoder.readMajorType(CBORBase.TYPE_BYTE_STRING);
            short readerAuthPubKeyOffset = mCBORDecoder.getCurrentOffsetAndIncrease(readerAuthPubKeyLen);
            short readerSignLen = mCBORDecoder.readMajorType(CBORBase.TYPE_BYTE_STRING);
            short readerSignOffset = mCBORDecoder.getCurrentOffsetAndIncrease(readerSignLen);

            if (!authenticateReader(receiveBuffer, transcriptOffset, transcriptLen, receiveBuffer,
                    readerAuthPubKeyOffset, readerAuthPubKeyLen, receiveBuffer, readerSignOffset, readerSignLen)) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            
            if(!getStatusFlag(STATUS_TRANSCRIPT_LOADED)) {
                cryptoManager.startRetrievalSignature(receiveBuffer, transcriptOffset, transcriptLen);
                setStatusFlag(STATUS_TRANSCRIPT_LOADED);
            }
            
            mStatusWords[VALUE_READER_KEY_LENGTH] = readerAuthPubKeyLen; 
            Util.arrayCopyNonAtomic(receiveBuffer, readerAuthPubKeyOffset, mTempBuffer, BUFFERPOS_READERKEY, readerAuthPubKeyLen);
            
            setStatusFlag(STATUS_READER_AUTHENTICATED);
        } else if (p1p2 == 0x2) { // User authentication
            if (getStatusFlag(STATUS_USER_AUTHENTICATED)) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED); // Already authenticated
            }
            
            len = mCBORDecoder.readMajorType(CBORBase.TYPE_BYTE_STRING);
            short tokenOffset = mCBORDecoder.getCurrentOffsetAndIncrease(len);

            if (!authenticateUser(receiveBuffer, tokenOffset, len)) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            setStatusFlag(STATUS_USER_AUTHENTICATED);
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    /**
     * Process the LOAD ACCESS CONTROL PROFILE command. Will throw an exception if
     * integrity check fails or the specified authentication criteria is not met.
     * 
     * @param cryptoManager Reference to the cryptomanager that performs the integrity check
     */
    public void processLoadAccessControlProfile(CryptoManager cryptoManager) {
        short receivingLength = mAPDUManager.receiveAll();
        byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();
        short inOffset = mAPDUManager.getOffsetIncomingData();

        if (Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != 0x0) { 
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        
        mAPDUManager.setOutgoing();

        mCBORDecoder.init(receiveBuffer, inOffset, receivingLength);
        mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);

        // Start location of the profile
        short profileOffset = mCBORDecoder.getCurrentOffset();
        
        // Skip the actual access control profile (we will only encrypt it
        short profileLength = (short)(mCBORDecoder.skipEntry() - profileOffset);

        short tagOffset = mCBORDecoder.getCurrentOffset();
        
        try {
            cryptoManager.verifyAuthenticationTag(receiveBuffer, profileOffset, profileLength, receiveBuffer, tagOffset);

            // Success: check if authentication is valid for this profile and store the id  
            mCBORDecoder.init(receiveBuffer, profileOffset, receivingLength);
            
            short mapSize = mCBORDecoder.readMajorType(CBORBase.TYPE_MAP);
            
            // Read keys and ignore them, we assume a fixed structure
            mCBORDecoder.increaseOffset(mCBORDecoder.readMajorType(CBORBase.TYPE_TEXT_STRING)); 
            byte pId = mCBORDecoder.readInt8();
            
            if (mapSize >= 2) {
                short keyLength = mCBORDecoder.readMajorType(CBORBase.TYPE_TEXT_STRING);
                mCBORDecoder.increaseOffset(keyLength);
                
                if(keyLength == LENGTH_MAPKEY_READERAUTHPUBKEY) { // No exact match check needed
                    // reader authentication, check if public key matches the authenticated pub key
                    if (!getStatusFlag(STATUS_READER_AUTHENTICATED)) { // No reader authentication performed
                        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                    }
                    
                    // TODO: Handle public key certificate chain 
                    short readerKeyLength = mCBORDecoder.readMajorType(CBORBase.TYPE_BYTE_STRING);
                    if (Util.arrayCompare(mTempBuffer, BUFFERPOS_READERKEY, receiveBuffer,
                            mCBORDecoder.getCurrentOffsetAndIncrease(readerKeyLength), readerKeyLength) != 0) {
                        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                    }
                }
                
                if(mCBORDecoder.getCurrentOffset() != tagOffset) { // more data --> user authentication 
                    if (!getStatusFlag(STATUS_USER_AUTHENTICATED)) { // No user authentication performed
                        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                    }
                    // userAuthType
                    short type = mCBORDecoder.readMajorType(CBORBase.TYPE_UNSIGNED_INTEGER);
                    
                    // userSecureId
                    keyLength = mCBORDecoder.readMajorType(CBORBase.TYPE_TEXT_STRING);
                    mCBORDecoder.increaseOffset(keyLength);
                    short secureIdSize = mCBORDecoder.getIntegerSize();
                    if(secureIdSize == 1) { // Handle special case of 1 byte integers, which is not supported
                        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                    } else {
                        mCBORDecoder.increaseOffset((short) 1); // jump to actual value
                        
                        if (Util.arrayCompare(mTempBuffer, BUFFERPOS_USERID, receiveBuffer ,
                                mCBORDecoder.getCurrentOffsetAndIncrease(secureIdSize), secureIdSize) != 0) {
                            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                        }
                    }
                    
                    // TODO: check timeout + type
                }
            } 
            // All authentications validated (or no authentication was required for this profile)
            addValidProfileId(pId);
            
        } catch (CryptoException e) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    /**
     * Check if one of the given access control profile IDs have been successfully
     * loaded and successfully verified.
     * 
     * @param pids Buffer that holds the profile IDs that should be checked. Each byte represents one profile
     * @param offset Offset into the buffer
     * @param length Length/Number of profile IDs 
     * @return True if one of the profile IDs has been successfully authenticated.
     */
    public boolean checkAccessPermission(byte[] pids, short offset, short length) {
        // We assume that the stored profile ids and the referenced pids are sorted
        short storedIds = (short) (BUFFERPOS_PROFILEIDS + mStatusWords[VALUE_VALID_PROFILE_IDS]);
        length = (short) (length+offset); // Add offset to length for faster check in loop
        
        short storedIdsStart = BUFFERPOS_PROFILEIDS;
        
        while(storedIdsStart < storedIds && offset < length) {
            if (pids[offset] == mTempBuffer[storedIdsStart]) {
                return true;
            } else if (pids[offset] > mTempBuffer[storedIdsStart]) {
                storedIdsStart++;
            } else {
                offset++;
            }
        }

        return false;
    }
}
