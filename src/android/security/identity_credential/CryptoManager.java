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

import com.nxp.id.jcopx.security.CryptoBaseX;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

public class CryptoManager {

    private static final byte FLAG_TEST_CREDENTIAL = 0;
    private static final byte FLAG_CREDENIAL_KEYS_INITIALIZED = 1;
    private static final byte FLAG_CREDENIAL_PERSONALIZATION_STATE = 2;
    private static final byte FLAG_CREDENIAL_PERSONALIZING_PROFILES = 3;
    private static final byte FLAG_CREDENIAL_PERSONALIZING_ENTRIES = 4;
    private static final byte FLAG_CREDENIAL_PERSONALIZING_NAMESPACE = 5;
    private static final byte FLAG_CREDENIAL_RETRIEVAL_STARTED = 6;
    private static final byte FLAG_CREDENIAL_RETRIEVAL_ENTRIES = 7;
    private static final byte FLAG_CREDENIAL_RETRIEVAL_CHUNKED = 8;
    private static final byte FLAG_CREDENIAL_RETRIEVAL_NAMESPACE = 9;
    private static final byte STATUS_FLAGS_SIZE = 2;

    private static final short TEMP_BUFFER_SIZE = 128;
    private static final short TEMP_BUFFER_DOCTYPE_MAXSIZE = 64;
    private static final short TEMP_BUFFER_DOCTYPE_POS = TEMP_BUFFER_SIZE;
    private static final short TEMP_BUFFER_IV_POS = TEMP_BUFFER_DOCTYPE_POS + TEMP_BUFFER_DOCTYPE_MAXSIZE;

    private static final byte STATUS_PROFILES_TOTAL = 0;
    private static final byte STATUS_PROFILES_PERSONALIZED = 1;
    private static final byte STATUS_ENTRIES_IN_NAMESPACE_TOTAL = 2;
    private static final byte STATUS_ENTRIES_IN_NAMESPACE = 3;
    private static final byte STATUS_ENTRY_AUTHDATA_LENGTH = 4;
    private static final byte STATUS_NAMESPACES_ADDED = 5;
    private static final byte STATUS_NAMESPACES_TOTAL = 6;
    private static final byte STATUS_DOCTYPE_LEN = 7;
    private static final byte STATUS_EPHKEY_LEN = 8;
    private static final byte STATUS_WORDS = 9;
    
    public static final byte AES_GCM_KEY_SIZE = 16; 
    public static final byte AES_GCM_IV_SIZE = 12;
    public static final byte AES_GCM_TAG_SIZE = CryptoBaseX.AES_GCM_TAGLEN_128;
    public static final byte EC_KEY_SIZE = 32;
    public static final byte DIGEST_SIZE = 32;

    /**
     * Static ephemeral key for testing
     */
//    private static final byte[] TESTEPH_KEY = new byte[] { (byte) 0x04, (byte) 0x0E, (byte) 0xFE, (byte) 0x2F,
//            (byte) 0x68, (byte) 0xC2, (byte) 0xA6, (byte) 0xB2, (byte) 0x15, (byte) 0xA0, (byte) 0x13, (byte) 0xFF,
//            (byte) 0xB4, (byte) 0xDC, (byte) 0xAB, (byte) 0x62, (byte) 0x0F, (byte) 0xE0, (byte) 0xCE, (byte) 0xCE,
//            (byte) 0xAE, (byte) 0x90, (byte) 0xA6, (byte) 0x17, (byte) 0xA2, (byte) 0x23, (byte) 0xB5, (byte) 0x1A,
//            (byte) 0x71, (byte) 0x2B, (byte) 0xF2, (byte) 0xFE, (byte) 0xE2, (byte) 0x84, (byte) 0x75, (byte) 0xCF,
//            (byte) 0x67, (byte) 0xE1, (byte) 0xF9, (byte) 0x68, (byte) 0xF8, (byte) 0x0A, (byte) 0xA1, (byte) 0x6F,
//            (byte) 0xEF, (byte) 0xEE, (byte) 0x5F, (byte) 0xA5, (byte) 0xF3, (byte) 0xA1, (byte) 0xE4, (byte) 0x9C,
//            (byte) 0x7C, (byte) 0x1B, (byte) 0x86, (byte) 0xEB, (byte) 0xF2, (byte) 0x87, (byte) 0x97, (byte) 0xDC,
//            (byte) 0x9C, (byte) 0x7D, (byte) 0x62, (byte) 0xAA, (byte) 0xF6 };
    
    // Hardware bound key, initialized during Applet installation
    private final AESKey mHBK;
    
    // Test key, initialized with only zeros during Applet installation
    private final AESKey mTestKey;

    // Storage key for a credential
    private final AESKey mCredentialStorageKey;

    // KeyPair for credential key generation 
    private final KeyPair mCredentialECKeyPair;

    // KeyPair for ephemeral key generation
    private final KeyPair mTempECKeyPair;
    
    // Signature object for creating and verifying credential signatures 
    private final Signature mECSignature;

    // Signature object for creating and verifying credential signatures 
    private final MessageDigest mDigest;
    
    // Random data generator 
    private final RandomData mRandomData;
    //TODO: implement my own counter based IV generator
    
    // Reference to the internal APDU manager instance
    private final APDUManager mAPDUManager;
    
    // Reference to the Access control manager instance
    private final AccessControlManager mAccessControlManager;
    
    // Reference to the internal CBOR decoder instance
    private final CBORDecoder mCBORDecoder;
    
    // Reference to the internal CBOR encoder instance
    private final CBOREncoder mCBOREncoder;

    // Temporary buffer for all cryptography operations
    private final byte[] mTempBuffer;
    
    // Temporary buffer in memory for status flags
    private final byte[] mStatusFlags;

    // Temporary buffer in memory for status information
    private final short[] mStatusWords;


    public CryptoManager(APDUManager apduManager, AccessControlManager accessControlManager, CBORDecoder decoder, CBOREncoder encoder) {
        mTempBuffer = JCSystem.makeTransientByteArray((short) (TEMP_BUFFER_SIZE + TEMP_BUFFER_DOCTYPE_MAXSIZE + AES_GCM_IV_SIZE),
                JCSystem.CLEAR_ON_DESELECT);

        mStatusFlags = JCSystem.makeTransientByteArray((short)(STATUS_FLAGS_SIZE), JCSystem.CLEAR_ON_DESELECT);
        mStatusWords = JCSystem.makeTransientShortArray(STATUS_WORDS, JCSystem.CLEAR_ON_DESELECT);
        
        // Secure Random number generation for HBK
        mRandomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        mRandomData.generateData(mTempBuffer, (short)0, AES_GCM_KEY_SIZE);
        mHBK = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        mHBK.setKey(mTempBuffer, (short)0);
        
        // Overwrite this new HBK key in the buffer and initialize a test key 
        Util.arrayFillNonAtomic(mTempBuffer, (short) 0, AES_GCM_KEY_SIZE, (byte) 0);
        mTestKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        mTestKey.setKey(mTempBuffer, (short)0);

        // Create the storage key instance 
        mCredentialStorageKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, false);
        
        // Configure key pair for elliptic curve key generation
        mCredentialECKeyPair = new KeyPair(
                (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false),
                (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT, KeyBuilder.LENGTH_EC_FP_256, false));
        
        mTempECKeyPair = new KeyPair(
                (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false),
                (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT, KeyBuilder.LENGTH_EC_FP_256, false));

        // At the moment we only support SEC-P256r1. Hence, can be configured at install time.
        Secp256r1.configureECKeyParameters((ECKey) mCredentialECKeyPair.getPrivate());
        Secp256r1.configureECKeyParameters((ECKey) mCredentialECKeyPair.getPublic());
        Secp256r1.configureECKeyParameters((ECKey) mTempECKeyPair.getPrivate());
        Secp256r1.configureECKeyParameters((ECKey) mTempECKeyPair.getPublic());

        // Initialize the object for signing data using EC
        mECSignature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        
        mDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        
        mAPDUManager = apduManager;
        mAccessControlManager = accessControlManager;
        mCBORDecoder = decoder;
        mCBOREncoder = encoder;
    }

    /**
     * Reset the internal state. Resets the credential private key, the storage key
     * as well as all status flags.
     */
    public void reset() {
        ICUtil.setBit(mStatusFlags, FLAG_TEST_CREDENTIAL, false);
        ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_KEYS_INITIALIZED, false);
        ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_PERSONALIZATION_STATE, false);
        ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_PERSONALIZING_PROFILES, false);
        ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_PERSONALIZING_NAMESPACE, false);
        ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_RETRIEVAL_STARTED, false);
        ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_RETRIEVAL_ENTRIES, false);
        ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_RETRIEVAL_CHUNKED, false);
        ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_RETRIEVAL_NAMESPACE, false);
        
        mStatusWords[STATUS_ENTRIES_IN_NAMESPACE] = 0;
        mStatusWords[STATUS_ENTRIES_IN_NAMESPACE_TOTAL] = 0;
        mStatusWords[STATUS_ENTRY_AUTHDATA_LENGTH] = 0;
        mStatusWords[STATUS_DOCTYPE_LEN] = 0;
        mStatusWords[STATUS_EPHKEY_LEN] = 0;
        
        ICUtil.shortArrayFillNonAtomic(mStatusWords, (short) 0, STATUS_WORDS, (short) 0);

        mCredentialStorageKey.clearKey();
        mCredentialECKeyPair.getPrivate().clearKey();
        Secp256r1.configureECKeyParameters((ECKey) mCredentialECKeyPair.getPrivate());
    }
    
    /**
     * Process an APDU related to the cryptomanager. Throws
     * {@value ISO7816#SW_INS_NOT_SUPPORTED} if the instruction byte was not
     * processed.
     */
    public void process() {
        byte[] buf = mAPDUManager.getReceiveBuffer();
        switch(buf[ISO7816.OFFSET_INS]) {
        case ISO7816.INS_ICS_CREATE_EPHEMERAL_KEY:
            processCreateEphemeralKey();
            break;
        case ISO7816.INS_ICS_CREATE_CREDENTIAL:
            processCreateCredential();
            break;
        case ISO7816.INS_ICS_GET_ATTESTATION_CERT:
            processGetAttestationCertificate();
            break;
        case ISO7816.INS_ICS_PERSONALIZE_ACCESS_CONTROL:
            processPersonalizeAccessControl();
            break;
        case ISO7816.INS_ICS_PERSONALIZE_NAMESPACE:
            processPersonalizeNamespace();
            break;
        case ISO7816.INS_ICS_PERSONALIZE_ATTRIBUTE:
            processPersonalizeDataAttribute();
            break;
        case ISO7816.INS_ICS_SIGN_PERSONALIZED_DATA:
            processSignPersonalizedData();
            break;
        case ISO7816.INS_ICS_LOAD_CREDENTIAL_BLOB:
            processLoadCredentialBlob();
            break;       
        case ISO7816.INS_ICS_GET_NAMESPACE:
            processGetNameSpace();
            break;
        case ISO7816.INS_ICS_GET_ENTRY:
            processGetEntry();
            break;
        case ISO7816.INS_ICS_CREATE_SIGNING_KEY:
            processGenerateSigningKeyPair();
            break;
        case ISO7816.INS_ICS_CREATE_SIGNATURE:
            processSignDataRequest();
            break;
        default: 
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    /**
     * Returns the used AES key size for the storage as well as hardware-bound key
     * in bit.
     */
    public short getAESKeySize() {
        return (short) (AES_GCM_KEY_SIZE * 8);
    }
    
    /**
     * Process the CREATE EPHEMERAL KEY command.
     */
    private void processCreateEphemeralKey() throws ISOException {
        mAPDUManager.receiveAll();
        byte[] buf = mAPDUManager.getReceiveBuffer();
        
        // Check P1P2
        if((buf[ISO7816.OFFSET_P1] & 0x80) == 0x80) { // Load the provided ephemeral keys

            mCBORDecoder.init(buf, mAPDUManager.getOffsetIncomingData(), mAPDUManager.getReceivingLength());
            mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);

            // Start location of the public key
            short ecPubKeyLength = mCBORDecoder.readLength();
            short ecPubKeyOffset = mCBORDecoder.getCurrentOffsetAndIncrease(ecPubKeyLength);

            mCBORDecoder.readLength();
            short tagValueOffset = mCBORDecoder.getCurrentOffset();

            if (!verifyAuthenticationTag(buf, ecPubKeyOffset, ecPubKeyLength, buf, tagValueOffset)) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            ((ECPublicKey) mTempECKeyPair.getPublic()).setW(buf, ecPubKeyOffset, ecPubKeyLength);
        } else {
            switch (Util.getShort(buf, ISO7816.OFFSET_P1)) {
            case 0: // Do nothing
                break;
            case 1: // EC_NIST_P_256            
                mAPDUManager.setOutgoing();
                
                // Create the ephemeral key
                mTempECKeyPair.genKeyPair();
                
                // Keep the ephemeral key in the key object
                short length = ((ECPublicKey) mTempECKeyPair.getPublic()).getW(mTempBuffer, (short) 0);
                
                // Start the CBOR encoding of the output 
                mCBOREncoder.init(mAPDUManager.getSendBuffer(), (short) 0, mAPDUManager.getOutbufferLength());
                mCBOREncoder.startArray((short) 3);
                
                mCBOREncoder.encodeByteString(mTempBuffer, (short) 0, length);
                
                // Get the private key and append it to the output
                short encodedLocation = mCBOREncoder.startByteString(EC_KEY_SIZE);
    
                ((ECPrivateKey) mTempECKeyPair.getPrivate()).getS(mAPDUManager.getSendBuffer(), encodedLocation);
                
                // Compute the mac of the public key and append it to the output
                encodedLocation = mCBOREncoder.startByteString((short) (AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE));
                encryptCredentialData(mTempBuffer, (short) 0, (short) 0,  // No data input
                        mTempBuffer, (short) 0, length, // Public key as auth data 
                        mAPDUManager.getSendBuffer(), encodedLocation); // Output data
                
                mAPDUManager.setOutgoingLength(mCBOREncoder.getCurrentOffset());
                break;
            default: 
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
        }
    }

    /**
     * Process the CREATE CREDENTIAL command. Outputs the encrypted credential blob
     */
    private void processCreateCredential() throws ISOException{        
        short receivingLength = mAPDUManager.receiveAll();
        byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();
        short inOffset = mAPDUManager.getOffsetIncomingData();
        
        mAPDUManager.setOutgoing();
        byte[] outBuffer = mAPDUManager.getSendBuffer();

        AESKey encryptionKey = mHBK; 

        // Check if it is a test credential
        if(Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) == 0x1) { // Test credential
            ICUtil.setBit(mStatusFlags, FLAG_TEST_CREDENTIAL, true);

            encryptionKey = mTestKey;
        } else if(Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != 0x0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        
        if (receivingLength == 0) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        
        // Encoding the output as bstr
        mCBOREncoder.init(outBuffer, (short) 0, mAPDUManager.getOutbufferLength());

        short outOffset = mCBOREncoder.startByteString((short) (4 // CBOR structure with 5 bytes = 1 array start + 1 STK bstr + 2 CRK bstr   
                + AES_GCM_IV_SIZE + AES_GCM_KEY_SIZE + EC_KEY_SIZE + AES_GCM_TAG_SIZE));

        // Generate the AES-128 storage key 
        mRandomData.generateData(mTempBuffer, (short) 0, AES_GCM_KEY_SIZE);
        mCredentialStorageKey.setKey(mTempBuffer, (short) 0);

        // Create a new credential key
        mCredentialECKeyPair.genKeyPair();

        // Credential keys are loaded
        ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_KEYS_INITIALIZED, true);

        // Set the Applet in the PERSONALIZATION state
        ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_PERSONALIZATION_STATE, true);
        
        
        // Return credentialBlob and start signature creation
        try {
            // encrypt storage key and credential key for returning
            outOffset += wrapCredentialBlob(encryptionKey, receiveBuffer, inOffset, receivingLength, outBuffer, outOffset);
            
            // Initialize the signature creation object
            mECSignature.init(mCredentialECKeyPair.getPrivate(), Signature.MODE_SIGN);
            
            // Add doc type to the signature {"docType" : tstr, ...
            mCBOREncoder.init(mTempBuffer, (short) 0, TEMP_BUFFER_SIZE);
            mCBOREncoder.startMap((short) 4);
            mCBOREncoder.encodeTextString(ICConstants.CBOR_MAPKEY_DOCTYPE, (short) 0,
                    (short) ICConstants.CBOR_MAPKEY_DOCTYPE.length);
            mCBOREncoder.encodeTextString(receiveBuffer, inOffset, receivingLength);
            
            mECSignature.update(mTempBuffer, (short) 0, mCBOREncoder.getCurrentOffset());
            
            mAPDUManager.setOutgoingLength(outOffset);
        } catch (CryptoException e) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    /**
     * Wrap the credential keys into an credential blob.
     * 
     * @param encryptionKey     The encryption that should be used.
     * @param outCredentialBlob Output buffer for the credentialBlob
     * @param outOffset         Offset in the buffer
     * @return Bytes written in the output buffer
     */
    private short wrapCredentialBlob(AESKey encryptionKey, byte[] docType, short docTypeOffset, short docTypeLen,
            byte[] outCredentialBlob, short outOffset) throws CryptoException {
        // Encoder for the CredentialKeys blob
        mCBOREncoder.init(mTempBuffer, (short) 0, TEMP_BUFFER_SIZE);
        // Encode an array consisting of [storageKey, credentialPrivKey]
        mCBOREncoder.startArray((short) 2);  
        
        // Copy the credential storage key into the temp buffer
        mCredentialStorageKey.getKey(mTempBuffer, mCBOREncoder.startByteString(AES_GCM_KEY_SIZE));
        
        // Copy the credential private key in the tempBuffer
        ((ECPrivateKey) mCredentialECKeyPair.getPrivate()).getS(mTempBuffer, mCBOREncoder.startByteString(EC_KEY_SIZE));

        short dataLength = mCBOREncoder.getCurrentOffset();
        // Generate the IV
        mRandomData.generateData(outCredentialBlob, (short) outOffset, (short) AES_GCM_IV_SIZE);
        
        // Encrypt and return the size of the result (credentialBlob)
        return (short) (CryptoBaseX.doFinal(encryptionKey, CryptoBaseX.ALG_AES_GCM, // Key information
                Cipher.MODE_ENCRYPT, mTempBuffer, (short) 0, dataLength, // Data (keys)
                outCredentialBlob, outOffset, AES_GCM_IV_SIZE, // IV
                docType, docTypeOffset, docTypeLen, 
                outCredentialBlob, (short) (outOffset + AES_GCM_IV_SIZE), // Output location
                outCredentialBlob, (short) (outOffset + AES_GCM_IV_SIZE + dataLength), // Tag output
                AES_GCM_TAG_SIZE) + AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE); 
    }

    /**
     * Process the LOAD CREDENTIAL command. Throws an exception if decryption is
     * unsuccessful
     */
    private void processLoadCredentialBlob() throws ISOException {
        short receivingLength = mAPDUManager.receiveAll();
        byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();
        short inOffset = mAPDUManager.getOffsetIncomingData();
        
        AESKey encryptionKey = mHBK; 

        if(Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != 0x0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        
        try {
            if(receivingLength <= (short)(inOffset+AES_GCM_IV_SIZE+AES_GCM_TAG_SIZE)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);    
            }
            mCBORDecoder.init(receiveBuffer, inOffset, receivingLength);
            mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);
            
            short strLen = mCBORDecoder.readMajorType(CBORBase.TYPE_TEXT_STRING);
            
            // Save DocType
            Util.arrayCopyNonAtomic(receiveBuffer,
                    mCBORDecoder.getCurrentOffsetAndIncrease(strLen), mTempBuffer, TEMP_BUFFER_DOCTYPE_POS, strLen);
            mStatusWords[STATUS_DOCTYPE_LEN] = strLen;
            
            if (mCBORDecoder.readBoolean()) {
                // Test credential
                encryptionKey = mTestKey;
                ICUtil.setBit(mStatusFlags, FLAG_TEST_CREDENTIAL, true);
            } else {
                ICUtil.setBit(mStatusFlags, FLAG_TEST_CREDENTIAL, false);
            }
            
            // Read credential keys
            if((strLen = mCBORDecoder.readMajorType(CBORBase.TYPE_BYTE_STRING)) <= 0){
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);    
            }
            
            if (!unwrapCredentialBlob(encryptionKey, receiveBuffer, mTempBuffer, TEMP_BUFFER_DOCTYPE_POS, mStatusWords[STATUS_DOCTYPE_LEN], mCBORDecoder.getCurrentOffsetAndIncrease(strLen),
                    strLen)) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
        } catch(CryptoException e) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }
    
    private boolean unwrapCredentialBlob(AESKey encryptionKey, byte[] credentialBlob, byte[] docType,
            short docTypeOffset, short docTypeLen, short offset, short length) throws CryptoException {
        short outLen = CryptoBaseX.doFinal(encryptionKey, CryptoBaseX.ALG_AES_GCM, Cipher.MODE_DECRYPT, // Key information
                credentialBlob, (short) (offset + AES_GCM_IV_SIZE), (short) (length - AES_GCM_IV_SIZE - AES_GCM_TAG_SIZE), // Data
                credentialBlob, offset, AES_GCM_IV_SIZE, // IV
                docType, docTypeOffset, docTypeLen, // AuthData
                mTempBuffer, (short) 0, // Output location
                credentialBlob, (short) (offset + length - AES_GCM_TAG_SIZE), // Tag input
                AES_GCM_TAG_SIZE); 
        
        mCBORDecoder.init(mTempBuffer, (short) 0, outLen);
        if(mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY) == 2) {
            short len;
            if((len = mCBORDecoder.readMajorType(CBORBase.TYPE_BYTE_STRING)) < 0) {
                return false;   
            }
            
            if (len == AES_GCM_KEY_SIZE) {
                mCredentialStorageKey.setKey(mTempBuffer, mCBORDecoder.getCurrentOffsetAndIncrease(len));
                if((len = mCBORDecoder.readMajorType(CBORBase.TYPE_BYTE_STRING)) < 0) {
                    return false;   
                }
                
                if (len == EC_KEY_SIZE) {
                    ((ECPrivateKey)mCredentialECKeyPair.getPrivate()).setS(mTempBuffer, mCBORDecoder.getCurrentOffsetAndIncrease(len), len);

                    ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_KEYS_INITIALIZED, true);
                    return true;
                }
            }
        }
        return false;
    }
    
    /**
     * Process the GET ATTESTATION CERTIFICATE command. Throws an exception when the
     * credential is not loaded yet or the applet is not in personalization state.
     */
    private void processGetAttestationCertificate() {
        assertCredentialLoaded();
        assertInPersonalizationState();

        short receivingLength = mAPDUManager.receiveAll();
        byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();
        short inOffset = mAPDUManager.getOffsetIncomingData();

        mCBORDecoder.init(receiveBuffer, inOffset, receivingLength);
        // TODO decode the attestation challenge and the attestation id

        mAPDUManager.setOutgoing(true);
        byte[] outBuffer = mAPDUManager.getSendBuffer();
        mCBOREncoder.init(outBuffer, (short) 0, mAPDUManager.getOutbufferLength());

        // TODO let the keymaster sign the attestation certificate. For now, we make it
        // self signed

        // We don't know the actual size yet. To avoid copying it to temporary buffer,
        // we just make sure that sufficient space for the length field is allocated (2
        // bytes)
        short encodedLocation = mCBOREncoder.startByteString((short) 0x200);

        short certLen = createSigningKeyCertificate((ECPrivateKey) mCredentialECKeyPair.getPrivate(),
                (ECPublicKey) mCredentialECKeyPair.getPublic(), outBuffer, encodedLocation);

        // Set the actual size
        Util.setShort(outBuffer, (short) (encodedLocation - 2), certLen);

        mAPDUManager.setOutgoingLength((short) (encodedLocation + certLen));
    }

    /**
     * Process the PERSONALIZE NAMESPACE command. Throws an exception when the
     * applet is not in personalization state, profiles are not personalized yet, or
     * previous namespace is not finished with personalization.
     */
    private void processPersonalizeNamespace() {
        assertInPersonalizationState();
        assertStatusFlagNotSet(FLAG_CREDENIAL_PERSONALIZING_PROFILES);
        
        short receivingLength = mAPDUManager.receiveAll();
        byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();
        short inOffset = mAPDUManager.getOffsetIncomingData();

        mCBOREncoder.init(mTempBuffer, (short) 0, TEMP_BUFFER_SIZE);
        
        if(!ICUtil.getBit(mStatusFlags, FLAG_CREDENIAL_PERSONALIZING_ENTRIES) && mStatusWords[STATUS_NAMESPACES_ADDED] == 0) {
            // First namespace get the total number of namespaces from P1(lower 4 bits) + P2
            mStatusWords[STATUS_NAMESPACES_TOTAL] = (short) ((((short) receiveBuffer[ISO7816.OFFSET_P1] & 0x0F) << 8)
                    + receiveBuffer[ISO7816.OFFSET_P2]);

            // Add the text string "namespaces" and the beginning of the array to the signature
            mCBOREncoder.encodeTextString(ICConstants.CBOR_MAPKEY_NAMESPACES, (short) 0,
                    (short) ICConstants.CBOR_MAPKEY_NAMESPACES.length); 
            mCBOREncoder.startMap(mStatusWords[STATUS_NAMESPACES_TOTAL]);

            // Start personalization, reset the namespace counter
            mStatusWords[STATUS_NAMESPACES_ADDED] = 0;
            
            ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_PERSONALIZING_ENTRIES, true);
        } 
        
        // Check that current namespace is already finished with personalization
        if(!ICUtil.getBit(mStatusFlags, FLAG_CREDENIAL_PERSONALIZING_NAMESPACE)) {
            // Verify that we did not already already finish personalization
            assertStatusFlagSet(FLAG_CREDENIAL_PERSONALIZING_ENTRIES);

            decodeNamespaceForSigning(receiveBuffer, inOffset, receivingLength);
            
            ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_PERSONALIZING_NAMESPACE, true);
            mECSignature.update(mTempBuffer, (short) 0, mCBOREncoder.getCurrentOffset());
        } else {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }
    /**
     * Process PERSONALIZE DATA ATTRIBUTE command. Throws an exception if the
     * received CBOR structure is invalid or if the credential is not initialized.
     */
    private void processPersonalizeDataAttribute() throws ISOException {
        assertInPersonalizationState();
        assertStatusFlagNotSet(FLAG_CREDENIAL_PERSONALIZING_PROFILES);
        assertStatusFlagSet(FLAG_CREDENIAL_PERSONALIZING_NAMESPACE);
        assertStatusFlagSet(FLAG_CREDENIAL_PERSONALIZING_ENTRIES);
            
        short receivingLength = mAPDUManager.receiveAll();
        byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();
        short inOffset = mAPDUManager.getOffsetIncomingData();
        boolean directlyAvailable = false;
        
        // Check P1P2
        if((receiveBuffer[ISO7816.OFFSET_P1] & 0x80) == 0x80) { // Directly available data = first bit in P1 set
            directlyAvailable = true;
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);  // Not implemented yet   
        }    

        mAPDUManager.setOutgoing(true);
        byte[] outBuffer = mAPDUManager.getSendBuffer();
        
        mCBORDecoder.init(receiveBuffer, inOffset, receivingLength);
        mCBOREncoder.init(outBuffer, (short) 0, mAPDUManager.getOutbufferLength());

        byte entryStatus = (byte) (receiveBuffer[ISO7816.OFFSET_P1] & 0x7); // Get status of entry personalization

        if (entryStatus == 0x0) { // Start entry: Additional data in command data
            // AdditionalData is encoded as map {namespace, name, accessControlProfileIds}
            
            // Add beginning of entry to signature (get name and ACP from authentication data)
            // Entry in signature is structured as Map = { "name" : tstr, 
            //           "accessControlProfiles" : [ *uint],
            //           "value" : bstr / tstr / int / bool,
            //           "directlyAvailable" : bool }
            
            // Get name and accesscontrolProfileIds from addData 
            mCBORDecoder.readMajorType(CBORBase.TYPE_MAP);
            
            mCBORDecoder.skipEntry(); // Skip "namespace"
            mCBORDecoder.skipEntry(); // Skip namespace value
            
            short nameOffset = mCBORDecoder.getCurrentOffset();
            mCBORDecoder.skipEntry(); // Skip "name"
            mCBORDecoder.skipEntry(); // Skip name value
            mCBORDecoder.skipEntry(); // Skip "accessControlProfileIds"            
            short nameAndACPLength = (short) (mCBORDecoder.skipEntry() - nameOffset);     
            
            // Add  {"name" : tstr, "accessControlProfiles" : [ *uint] to signature, "value" : ...}
            mCBOREncoder.init(mTempBuffer, (short) 0, TEMP_BUFFER_SIZE);
            mCBOREncoder.startMap((short) 4);

            mECSignature.update(mTempBuffer, (short) 0, mCBOREncoder.getCurrentOffset());
            mECSignature.update(receiveBuffer, nameOffset, nameAndACPLength);
            
            mCBOREncoder.init(mTempBuffer, (short) 0, TEMP_BUFFER_SIZE);
            mCBOREncoder.encodeTextString(ICConstants.CBOR_MAPKEY_VALUE, (short) 0, (short) ICConstants.CBOR_MAPKEY_VALUE.length);
            
            // add map key "value" to the signature
            mECSignature.update(mTempBuffer, (short) 0, (short) mCBOREncoder.getCurrentOffset());
            
            storeAuthenticationData(receiveBuffer, inOffset, receivingLength);
        } else { // Entry value in command data : encrypt and return 
            // Additional data needs to be sent first
            if(mStatusWords[STATUS_ENTRY_AUTHDATA_LENGTH] == 0) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED); 
            }
            
            // EntryValue is encoded as CBOR value tstr / bstr / int / bool
            short dataOffset = mCBORDecoder.getCurrentOffset();
            
            // Length of the complete APDU
            short dataLength = mAPDUManager.getReceivingLength();            

            if ((entryStatus & 0x2) == 0x2) {
                // A chunk "inbetween": Do NOT add type and length to signature
                
                // Read length information (move offset to actual data)  
                mCBORDecoder.readLength();
                dataLength -= mCBORDecoder.getCurrentOffset() - dataOffset;
                dataOffset = mCBORDecoder.getCurrentOffset();
            }
            
            // Add entry to signature before encryption (same buffer might be used for receiving and sending)
            mECSignature.update(receiveBuffer, dataOffset, dataLength);
            
            // Encrypt and return
            short len = encryptCredentialData(receiveBuffer, inOffset, mAPDUManager.getReceivingLength(), mTempBuffer,
                    (short) 0, mStatusWords[STATUS_ENTRY_AUTHDATA_LENGTH], outBuffer, (short) 0);
            
            mAPDUManager.setOutgoingLength(len);
        }
        
        
        // If first bit is set: this command was the last (or only) chunk
        if ((entryStatus & 0x1) == 0x1) {
            // Add directly available bit information ("directlyAvailable" : bool) 
            mCBOREncoder.init(mTempBuffer, (short) 0, TEMP_BUFFER_SIZE);
            mCBOREncoder.encodeTextString(ICConstants.CBOR_MAPKEY_DIRECTLYAVAILABLE, (short) 0,
                    (short) ICConstants.CBOR_MAPKEY_DIRECTLYAVAILABLE.length);
            mCBOREncoder.encodeBoolean(directlyAvailable);
            mECSignature.update(mTempBuffer, (short) 0, mCBOREncoder.getCurrentOffset());
        
            mStatusWords[STATUS_ENTRY_AUTHDATA_LENGTH] = 0; // Reset entry information
            
            mStatusWords[STATUS_ENTRIES_IN_NAMESPACE]++;
            if(mStatusWords[STATUS_ENTRIES_IN_NAMESPACE] == mStatusWords[STATUS_ENTRIES_IN_NAMESPACE_TOTAL]) {
                // Finished with personalization of this namespace
                ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_PERSONALIZING_NAMESPACE, false);
                
                mStatusWords[STATUS_NAMESPACES_ADDED]++;
                
                if(mStatusWords[STATUS_NAMESPACES_ADDED] == mStatusWords[STATUS_NAMESPACES_TOTAL]) {
                    // All namespaces personalized
                    ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_PERSONALIZING_ENTRIES, false);
                }
            } 
        }

    }
    
    /**
     * Process the PERSONALIZE ACCESS CONTROL command. Throws an exception if
     * received CBOR structure is invalid or the credential is not initialized.
     */
    private void processPersonalizeAccessControl() throws ISOException {
        assertInPersonalizationState();
        assertStatusFlagNotSet(FLAG_CREDENIAL_PERSONALIZING_ENTRIES);

        short receivingLength = mAPDUManager.receiveAll();
        byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();
        short inOffset = mAPDUManager.getOffsetIncomingData();

        // Check P1P2
        if((receiveBuffer[ISO7816.OFFSET_P1] & 0x80) == 0x80) { // Directly available data = first bit in P1 set
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);  // Not implemented yet   
        }    
        
        if(!ICUtil.getBit(mStatusFlags, FLAG_CREDENIAL_PERSONALIZING_PROFILES)) {
            // First entry personalization request, get the total number of profiles from P2
            mStatusWords[STATUS_PROFILES_TOTAL] = (short) (receiveBuffer[ISO7816.OFFSET_P2] & 0xFF);
            
            // Add the text string "AccessControlProfile" and the start array to the signature
            mCBOREncoder.init(mTempBuffer, (short) 0, TEMP_BUFFER_SIZE);
            
            mCBOREncoder.encodeTextString(ICConstants.CBOR_MAPKEY_ACCESSCONTROLPROFILES, (short) 0,
                    (short) ICConstants.CBOR_MAPKEY_ACCESSCONTROLPROFILES.length);
            
            mCBOREncoder.startArray(mStatusWords[STATUS_PROFILES_TOTAL]);
            mECSignature.update(mTempBuffer, (short) 0, mCBOREncoder.getCurrentOffset());

            mStatusWords[STATUS_PROFILES_PERSONALIZED] = 0;
            
            ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_PERSONALIZING_PROFILES, true);
        }
        
        mAPDUManager.setOutgoing();
        byte[] outBuffer = mAPDUManager.getSendBuffer();

        mCBORDecoder.init(receiveBuffer, inOffset, receivingLength);
        mCBOREncoder.init(outBuffer, (short) 0, mAPDUManager.getOutbufferLength());
        
        short profileLength = 0, profileOffset = 0;
        short encodedLocation = 0;

        // Start location of the profile
        profileOffset = mCBORDecoder.getCurrentOffset();
        
        // Skip the actual access control profile (we will only encrypt it
        profileLength = (short)(mCBORDecoder.skipEntry() - profileOffset);
        
        // Add the profile to the signature
        mECSignature.update(receiveBuffer, profileOffset, profileLength);
        
        // Compute the MAC of the profile and encode it as byte string
        encodedLocation = mCBOREncoder.startByteString((short) (AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE));
        encryptCredentialData(mTempBuffer, (short) 0, (short) 0,  // No data input
                receiveBuffer, profileOffset, profileLength, // Profile as auth data 
                outBuffer, encodedLocation); // Output data
        
        mStatusWords[STATUS_PROFILES_PERSONALIZED]++;
        if(mStatusWords[STATUS_PROFILES_PERSONALIZED] == mStatusWords[STATUS_PROFILES_TOTAL]) {
            // Finished with profile personalization
            ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_PERSONALIZING_PROFILES, false);
        } 

        mAPDUManager.setOutgoingLength(mCBOREncoder.getCurrentOffset());
    }

    /**
     * Process the SIGN PERSONALIZED DATA command. Throws an ISO exception if status
     * is not reached (no credential keys, not in personalization state)
     */
    private void processSignPersonalizedData() {
        assertCredentialLoaded();
        assertInPersonalizationState();

        // Check if personalization is finished
        assertStatusFlagNotSet(FLAG_CREDENIAL_PERSONALIZING_NAMESPACE);
        assertStatusFlagNotSet(FLAG_CREDENIAL_PERSONALIZING_PROFILES);

        byte[] buf = mAPDUManager.getReceiveBuffer();

        // Check P1P2
        if(Util.getShort(buf, ISO7816.OFFSET_P1) != 0x0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        
        mAPDUManager.setOutgoing();
        byte[] outBuffer = mAPDUManager.getSendBuffer();

        // Encode "teststring" : boolean
        mCBOREncoder.init(mTempBuffer, (short) 0, TEMP_BUFFER_SIZE);
        mCBOREncoder.encodeTextString(ICConstants.CBOR_MAPKEY_TESTCREDENTIAL, (short) 0,
                (short) ICConstants.CBOR_MAPKEY_TESTCREDENTIAL.length);
        mCBOREncoder.encodeBoolean(ICUtil.getBit(mStatusFlags, FLAG_TEST_CREDENTIAL));
        
        // Finish signature and send data
        short outLen = mECSignature.sign(mTempBuffer, (short) 0, mCBOREncoder.getCurrentOffset(), outBuffer, (short) 0);
        
        // Finish Applet personalization state
        ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_PERSONALIZATION_STATE, false);
        mAPDUManager.setOutgoingLength(outLen);
    }



    /**
     * Starts entry retrieval and initiates signature creation for retrieval and auditLogData. 
     * The structure of signature for retrieval:
     * signature is: 
     *  AuthenticatedData = { 
     *      "SessionTranscript" : any, 
     *      "Response" : { DocType => { + Namespace => DataItems } } }
     * Structure of AuditLogData
     *  AuditLogData = [
     *          "AuditLogEntry",
     *          requestHash : bstr,
     *          responseHash: bstr,
     *          previousAuditSignatureHash : bstr
     *     ]
     * 
     * @param readerAuthDataBuffer 
     * @param readerAuthDataOffset
     * @param readerAuthDataLen
     * @return True or false, indicating if the reader authentication data is valid or not
     */
    public void setReaderAuthenticationData(final byte[] readerAuthDataBuffer, final short readerAuthDataOffset,
            final short readerAuthDataLen, final short transcriptOffset, final short transcriptLen) {
        assertCredentialLoaded();
        assertInitializedCredentialKeys();
        
        // Create structure for AuditLogData and add it to the signature
        mECSignature.init(mCredentialECKeyPair.getPrivate(), Signature.MODE_SIGN);
        mCBOREncoder.init(mTempBuffer, (short) 0, TEMP_BUFFER_SIZE);
        mCBOREncoder.startArray((short)4);

        // Add "AuditLogEntry"
        mCBOREncoder.encodeTextString(ICConstants.CBOR_MAPKEY_AUDITLOGENTRY, (short) 0, (short) ICConstants.CBOR_MAPKEY_AUDITLOGENTRY.length);
        
        // Add requestHash
        mDigest.reset();
        mDigest.doFinal(readerAuthDataBuffer, readerAuthDataOffset, readerAuthDataOffset, mTempBuffer, mCBOREncoder.startByteString(DIGEST_SIZE));
        mECSignature.update(mTempBuffer, (short) 0, mCBOREncoder.getCurrentOffset());
        // responseHash and previousAdutiSignatureHash will be added in processSignDataRequest
        
        // Create structure for AuthenticatedData and add it to the digest object
        mDigest.reset();
        
        // Add {"SessionTranscript" : any
        mCBOREncoder.init(mTempBuffer, (short) 0, TEMP_BUFFER_SIZE);
        mCBOREncoder.startMap((short) 2);
        mCBOREncoder.encodeTextString(ICConstants.CBOR_MAPKEY_SESSIONTRANSCRIPT, (short) 0, (short) ICConstants.CBOR_MAPKEY_SESSIONTRANSCRIPT.length);
        
        mDigest.update(mTempBuffer, (short) 0, mCBOREncoder.getCurrentOffset());
        mDigest.update(readerAuthDataBuffer, transcriptOffset, transcriptLen);
        
        // Add "Response" : {
        mCBOREncoder.init(mTempBuffer, (short) 0, TEMP_BUFFER_SIZE);
        mCBOREncoder.encodeTextString(ICConstants.CBOR_MAPKEY_RESPONSE, (short) 0, (short) ICConstants.CBOR_MAPKEY_RESPONSE.length);
        mCBOREncoder.startMap((short) 1);
        
        // Add docType
        mCBOREncoder.encodeTextString(mTempBuffer, TEMP_BUFFER_DOCTYPE_POS, mStatusWords[STATUS_DOCTYPE_LEN]);        
        
        mDigest.update(mTempBuffer, (short) 0, mCBOREncoder.getCurrentOffset());
        
        ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_RETRIEVAL_STARTED, true);
        ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_RETRIEVAL_ENTRIES, false);
        ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_RETRIEVAL_NAMESPACE, false);
        
        // Make sure that temp buffer is not used as ephemeral key (needs to be loaded again)
        mStatusWords[STATUS_EPHKEY_LEN] = 0;
    }

    /**
     * Process GET NAMESPACE command. Throws an exception if the credential is not
     * initialized.
     */
    private void processGetNameSpace() throws ISOException {
        assertCredentialLoaded();
        assertStatusFlagSet(FLAG_CREDENIAL_RETRIEVAL_STARTED);
            
        short receivingLength = mAPDUManager.receiveAll();
        byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();
        short inOffset = mAPDUManager.getOffsetIncomingData();

        mCBOREncoder.init(mTempBuffer, (short) 0, TEMP_BUFFER_SIZE);

        if (!ICUtil.getBit(mStatusFlags, FLAG_CREDENIAL_RETRIEVAL_ENTRIES)
                && mStatusWords[STATUS_NAMESPACES_ADDED] == 0) {
            // First namespace get the total number of namespaces from P1(lower 4 bits) + P2
            mStatusWords[STATUS_NAMESPACES_TOTAL] = (short) ((((short) receiveBuffer[ISO7816.OFFSET_P1] & 0x0F) << 8)
                    + receiveBuffer[ISO7816.OFFSET_P2]);

            mCBOREncoder.startMap(mStatusWords[STATUS_NAMESPACES_TOTAL]);

            // Start personalization, reset the namespace counter
            mStatusWords[STATUS_NAMESPACES_ADDED] = 0;
            
            ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_RETRIEVAL_ENTRIES, true);
        } 
        
        // Verify that current namespace is already finished with retrieval
        if(!ICUtil.getBit(mStatusFlags, FLAG_CREDENIAL_RETRIEVAL_NAMESPACE)) {
            assertStatusFlagSet(FLAG_CREDENIAL_RETRIEVAL_ENTRIES); // Verify that there are still missing namespaces

            short namespaceNameOffset = decodeNamespaceForSigning(receiveBuffer, inOffset, receivingLength);
            short namespaceNameLen = (short) (mCBORDecoder.getCurrentOffset() - namespaceNameOffset);
            
            if (mAccessControlManager.isValidNamespace(receiveBuffer, namespaceNameOffset, namespaceNameLen)) {
                ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_RETRIEVAL_NAMESPACE, true);
                mDigest.update(mTempBuffer, (short) 0, mCBOREncoder.getCurrentOffset());
            } else {
                mStatusWords[STATUS_ENTRIES_IN_NAMESPACE_TOTAL] = 0;
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
        } else {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    /**
     * Read the namespace configuration from the CBOR structure in the received
     * buffer and creates the beginning of the CBOR structure for the signature into
     * the CBOR encoder.
     * 
     * @param receiveBuffer Reference to the receiving buffer
     * @param inOffset Offset in the receiving buffer
     * @param receivingLength Length of the data in the receiving buffer
     * @return Offset in the buffer where the namespace name begins
     */
    private short decodeNamespaceForSigning(byte[] receiveBuffer, short inOffset, short receivingLength) {
        mCBORDecoder.init(receiveBuffer, inOffset, receivingLength);
        mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);

        // Get the number of entries in this namespace
        mStatusWords[STATUS_ENTRIES_IN_NAMESPACE_TOTAL] = mCBORDecoder.readMajorType(CBORBase.TYPE_UNSIGNED_INTEGER);

        short namespaceNameLength = mCBORDecoder.readMajorType(CBORBase.TYPE_TEXT_STRING);
        short namespaceNameOffset = mCBORDecoder.getCurrentOffsetAndIncrease(namespaceNameLength);
        
        mCBOREncoder.encodeTextString(receiveBuffer, namespaceNameOffset, namespaceNameLength);
        mCBOREncoder.startArray(mStatusWords[STATUS_ENTRIES_IN_NAMESPACE_TOTAL]);

        // Reset counter for the number of entries in current namespace 
        mStatusWords[STATUS_ENTRIES_IN_NAMESPACE] = 0;
        
        return namespaceNameOffset;
    }
    
    /**
     * Process GET ENTRY command. Throws an exception if the credential is not
     * initialized, access control denies entry retrieval or if decryption fails.
     */
    private void processGetEntry() throws ISOException {
        assertCredentialLoaded();
        assertStatusFlagSet(FLAG_CREDENIAL_RETRIEVAL_ENTRIES);
        assertStatusFlagSet(FLAG_CREDENIAL_RETRIEVAL_NAMESPACE);
        
        short receivingLength = mAPDUManager.receiveAll();
        byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();
        short inOffset = mAPDUManager.getOffsetIncomingData();
        
        mAPDUManager.setOutgoing(true);
        byte[] outBuffer = mAPDUManager.getSendBuffer();
        
        mCBORDecoder.init(receiveBuffer, inOffset, receivingLength);
        mCBOREncoder.init(outBuffer, (short) 0, mAPDUManager.getOutbufferLength());

        byte entryStatus = (byte) (receiveBuffer[ISO7816.OFFSET_P1] & 0x7); // Get status of entry personalization
        
        if (entryStatus == 0x0) { // Start entry: Additional data in command data
            // AdditionalData is encoded as map {namespace, name, accessControlProfileIds}

            // Get name from authentication data and add signature 
            mCBORDecoder.readMajorType(CBORBase.TYPE_MAP);
            
            mCBORDecoder.skipEntry(); // Skip "namespace"
            mCBORDecoder.skipEntry(); // Skip namespace value
            
            mCBORDecoder.skipEntry(); // Skip "name" 
            short nameLength = mCBORDecoder.readLength();
            short nameOffset = mCBORDecoder.getCurrentOffsetAndIncrease(nameLength);

            // Add the actual name to the signature
            mDigest.update(receiveBuffer, nameOffset, nameLength);

            mCBORDecoder.skipEntry(); // Skip "AccessControlProfileIds"
            short nrOfPids = mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);

            if (mAccessControlManager.checkAccessPermission(receiveBuffer, mCBORDecoder.getCurrentOffset(), nrOfPids)
                    && mAccessControlManager.isNameInCurrentNamespaceConfig(receiveBuffer, nameOffset, nameLength)) {
                // Remember the whole additional data field for the data entry decryption 
                storeAuthenticationData(receiveBuffer, inOffset, receivingLength);
            } else {
                mStatusWords[STATUS_ENTRY_AUTHDATA_LENGTH] = 0;
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
        } else if (receivingLength != 0) { // Entry value in command data : decrypt and return
            // Additional data needs to be sent first
            if(mStatusWords[STATUS_ENTRY_AUTHDATA_LENGTH] == 0) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED); 
            }

            short len = 0;
            try {
                // Decrypt and return
                len = decryptCredentialData(receiveBuffer, inOffset, mAPDUManager.getReceivingLength(), outBuffer,
                        (short) 0);
            } catch (CryptoException e) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            
            short dataOffset = (short) 0;
            mCBORDecoder.init(outBuffer, dataOffset, len);
            
            if ((entryStatus & 0x2) == 0x2) {
                // A chunk "inbetween": Do NOT add type and length to signature
                
                // Read length information (move offset to actual data)  
                mCBORDecoder.readLength();
                dataOffset = mCBORDecoder.getCurrentOffset();
                len -= dataOffset;
            }
            
            // Indicate that data was successfully decrypted (required if a final
            // command without data is sent)
            ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_RETRIEVAL_CHUNKED, true); 
            
            // Add the value to the signature
            mDigest.update(receiveBuffer, dataOffset, len);
            
            mAPDUManager.setOutgoingLength(len);
        } else {
            mAPDUManager.setOutgoingLength((short) 0);
        }

        // If first bit is set: this command was the last (or only) chunk
        if ((entryStatus & 0x1) == 0x1 && ICUtil.getBit(mStatusFlags, FLAG_CREDENIAL_RETRIEVAL_CHUNKED)) {
            mStatusWords[STATUS_ENTRY_AUTHDATA_LENGTH] = 0; // Reset entry information
            
            mStatusWords[STATUS_ENTRIES_IN_NAMESPACE]++;
            if(mStatusWords[STATUS_ENTRIES_IN_NAMESPACE] == mStatusWords[STATUS_ENTRIES_IN_NAMESPACE_TOTAL]) {
                // Finished with retrieval of this namespace
                ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_RETRIEVAL_NAMESPACE, false);
                
                mStatusWords[STATUS_NAMESPACES_ADDED]++;
                
                if(mStatusWords[STATUS_NAMESPACES_ADDED] == mStatusWords[STATUS_NAMESPACES_TOTAL]) {
                    // All namespaces retrieved
                    ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_RETRIEVAL_ENTRIES, false);
                }
            } 
        }
    }

    /**
     * Save the authentication data of an entry into the temporary buffer. 
     * 
     * @param authDataBuffer
     * @param authDataOffset
     * @param authDataLength
     */
    private void storeAuthenticationData(byte[] authDataBuffer, short authDataOffset, short authDataLength) {
        if(authDataLength > TEMP_BUFFER_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        mStatusWords[STATUS_ENTRY_AUTHDATA_LENGTH] = authDataLength;
        Util.arrayCopyNonAtomic(authDataBuffer, authDataOffset, mTempBuffer, (short) 0, authDataLength);
    }
    

    /**
     * Encrypt the given data with the storage key using AES-GCM. The data output
     * format is R || encrypted data || Tag.
     * 
     * @param data           Input data that should be encrypted
     * @param offset         Offset in buffer
     * @param length         Length of data
     * @param authData       Authentication data
     * @param authDataOffset Offset of authentication data in buffer
     * @param authLen        Length of authentication data
     * @param outBuffer      Output buffer
     * @param outOffset      Offset in output buffer
     * 
     * @return Number of bytes written to output buffer
     */
    public short encryptCredentialData(byte[] data, short offset, short length, byte[] authData, short authDataOffset,
            short authLen, byte[] outBuffer, short outOffset) {
        assertCredentialLoaded();
        
        // Generate the IV
        mRandomData.generateData(mTempBuffer, TEMP_BUFFER_IV_POS, (short) AES_GCM_IV_SIZE);
        
        short len = CryptoBaseX.doFinal(mCredentialStorageKey, CryptoBaseX.ALG_AES_GCM, // Key information
                Cipher.MODE_ENCRYPT, data, offset, length, // Data
                mTempBuffer, TEMP_BUFFER_IV_POS, AES_GCM_IV_SIZE, // IV
                authData, authDataOffset, authLen, // authData 
                outBuffer, (short) (outOffset), // Output location
                outBuffer, (short) (outOffset + AES_GCM_IV_SIZE + length), // Tag output
                AES_GCM_TAG_SIZE);
        
        // Copy the IV to the end of the outbuffer
        Util.arrayCopyNonAtomic(mTempBuffer, TEMP_BUFFER_IV_POS, outBuffer, (short) (outOffset + length), AES_GCM_IV_SIZE);
        
        return (short) (len + AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE);
    }
    
    /**
     * Decrypt the given data with the storage key using AES-GCM. The input format
     * for data has to be R || encrypted data || Tag.
     * 
     * @param encryptedData  Input data that should be decrypted
     * @param offset         Offset in buffer
     * @param length         Length of data (including iv + tag) 
     * @param authData       Authentication data
     * @param authDataOffset Offset of authentication data in buffer
     * @param authLen        Length of authentication data
     * @param outBuffer      Output buffer for decrypted data
     * @param outOffset      Offset in output buffer
     * @return Number of bytes written to output buffer
     */
    public short decryptCredentialData(byte[] encryptedData, short offset, short length, byte[] authData,
            short authDataOffset, short authLen, byte[] outData, short outOffset) throws ISOException {
        assertCredentialLoaded();
        
        if(length < (short) (AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE)) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        
        return (short) (CryptoBaseX.doFinal(mCredentialStorageKey, CryptoBaseX.ALG_AES_GCM, Cipher.MODE_DECRYPT, // Key information
                encryptedData, (short) (offset), (short) (length - AES_GCM_IV_SIZE - AES_GCM_TAG_SIZE), // Data
                encryptedData, (short) (offset + length - AES_GCM_IV_SIZE - AES_GCM_TAG_SIZE), AES_GCM_IV_SIZE, // IV
                authData, authDataOffset, authLen, // authData 
                outData, outOffset, // Output location
                encryptedData, (short) (offset + length - AES_GCM_TAG_SIZE), // Tag location
                AES_GCM_TAG_SIZE)); 
    }

    public short decryptCredentialData(byte[] encryptedData, short offset, short length, byte[] outData,
            short outOffset) {
        // Authentication data needs to be sent first
        if(mStatusWords[STATUS_ENTRY_AUTHDATA_LENGTH] == 0) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED); 
        }
        
        return decryptCredentialData(encryptedData, offset, length, mTempBuffer, (short) 0,
                mStatusWords[STATUS_ENTRY_AUTHDATA_LENGTH], outData, outOffset);
    }


    /**
     * Process the GENERATE SIGNING KEY PAIR command. Throws an exception if the
     * credential is not initialized. Returns the encrypted signing key and the
     * X.509 certificate of the public signing key.
     */
    private void processGenerateSigningKeyPair() {
        assertCredentialLoaded();
        assertStatusFlagNotSet(FLAG_CREDENIAL_RETRIEVAL_STARTED);

        byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();
        
        if (Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != 0x01) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        
        mAPDUManager.setOutgoing(true);
        byte[] outBuffer = mAPDUManager.getSendBuffer();
        
        // Create the Signing key
        mTempECKeyPair.genKeyPair();
        
        short keyLen = ((ECPrivateKey)mTempECKeyPair.getPrivate()).getS(mTempBuffer, (short)0);
        
        // Start the CBOR encoding of the output 
        mCBOREncoder.init(outBuffer, (short) 0, mAPDUManager.getOutbufferLength());
        mCBOREncoder.startArray((short) 2);
        
        short encodedLocation = mCBOREncoder.startByteString((short) (AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE + keyLen));

        encryptCredentialData(mTempBuffer, (short) 0, keyLen, mTempBuffer, TEMP_BUFFER_DOCTYPE_POS,
                mStatusWords[STATUS_DOCTYPE_LEN], mAPDUManager.getSendBuffer(), encodedLocation);

        // We don't know the actual size yet. To avoid copying it to temporary buffer,
        // we just make sure that sufficient space for the length field is allocated (2 bytes)
        encodedLocation = mCBOREncoder.startByteString((short) 0x200); 

        short certLen = createSigningKeyCertificate((ECPrivateKey) mCredentialECKeyPair.getPrivate(),
                (ECPublicKey) mTempECKeyPair.getPublic(), outBuffer, encodedLocation);

        // Set the actual size
        Util.setShort(outBuffer, (short) (encodedLocation - 2), certLen);
        
        mAPDUManager.setOutgoingLength((short) (encodedLocation + certLen));
    }
    
    
    /**
     * Generate a x.509 certificate from the provided public key. Signs it with the
     * signing key. Note that it is only possible to generate a certificate with
     * fixed public key parameters and sizes. The base certificate format is defined
     * in {@link ICConstants#X509CERT_BASE}
     * 
     * @param signingKey           Key that should be used for signing the
     *                             certificate
     * @param publicKey            Public key that should be inserted into the
     *                             signature.
     * @param outCertificateBuffer Output buffer where the certificate should be
     *                             written.
     * @param outOffset            Offset into output buffer where the certificate
     *                             should be written.
     * @return Number of bytes written to output buffer.
     */
    private short createSigningKeyCertificate(ECPrivateKey signingKey, ECPublicKey publicKey,
            byte[] outCertificateBuffer, short outOffset) {
        short certLen = (short) ICConstants.X509_CERT_BASE.length;
        // Copy the base
        Util.arrayCopyNonAtomic(ICConstants.X509_CERT_BASE, (short) 0, outCertificateBuffer, outOffset, certLen);
        
        // Update the serial number (random 8 bytes)
        mRandomData.generateData(outCertificateBuffer, (short) (outOffset + ICConstants.X509_CERT_POS_SERIAL_NUM),
                ICConstants.X509_CERT_SERIAL_NUMBER_LEN);
        
        // TODO: add validity period: use time source from user authentication token?
        
        // Change public key
        short len = publicKey.getW(outCertificateBuffer, (short) (outOffset + ICConstants.X509_CERT_POS_PUB_KEY));

        // Do not sign the starting tag and the signing key information at the end of the cert
        short signingBegin = ICConstants.X509_CERT_POS_TOTAL_LEN + 1;
        short signingLen = (short) (ICConstants.X509_CERT_POS_PUB_KEY + len - signingBegin);
        
        // Sign and append signature to output
        mECSignature.init(signingKey, Signature.MODE_SIGN);
        short signatureOffset = (short) (outOffset + certLen);
        
        len = mECSignature.sign(outCertificateBuffer, signingBegin, signingLen, outCertificateBuffer,
                (short) (signatureOffset + 3)); // +3 to keep space for the tag information
        
        // Encode signature tag
        outCertificateBuffer[signatureOffset] = ICConstants.X509_CERT_TAG_BITSTRING;
        // We assume that the signature len fits in one byte (127) for now 
        outCertificateBuffer[(short) (signatureOffset + 1)] = (byte) (len + 1);
        outCertificateBuffer[(short) (signatureOffset + 2)] = 0; // Encapsulated signature
        
        // Final length (previously stored length + signature)
        len += 3 /* Tag info*/;
        outCertificateBuffer[(short) (outOffset + ICConstants.X509_CERT_POS_TOTAL_LEN)] += len; 
        return (short) (certLen + len);
    }

    /**
     * Process the signature creation request for data retrieval. Also computes the
     * final auditSignatureHash and returns both signatures (data request and audit
     * log signature) as well as the hash of the data entry response. Expects the
     * signing key blob as well as the previous audit log hash in the command apdu.
     */
    private void processSignDataRequest() {
        assertCredentialLoaded();
        assertStatusFlagSet(FLAG_CREDENIAL_RETRIEVAL_STARTED);
        assertStatusFlagNotSet(FLAG_CREDENIAL_RETRIEVAL_ENTRIES);

        short receivingLength = mAPDUManager.receiveAll();
        byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();
        short inOffset = mAPDUManager.getOffsetIncomingData();

        if (Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != 0x00) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        
        mAPDUManager.setOutgoing();
        byte[] outBuffer = mAPDUManager.getSendBuffer();
        
        // Input is encoded as createSignature = [
        //        bstr,   ; previousAuditSignatureHash
        //        bstr    ; signingKeyBlob 
        //   ]

        mCBORDecoder.init(receiveBuffer, inOffset, receivingLength);
        mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);
        
        // Include the type and length information 
        short previousHashOffset = mCBORDecoder.getCurrentOffset();
        short previousHashLen = mCBORDecoder.readMajorType(CBORBase.TYPE_BYTE_STRING);
        mCBORDecoder.increaseOffset(previousHashLen);
        
        // Get the signing key blob location and length
        short signingKeyBlobLen = mCBORDecoder.readMajorType(CBORBase.TYPE_BYTE_STRING);
        short signingKeyBlobOffset = mCBORDecoder.getCurrentOffsetAndIncrease(signingKeyBlobLen);
        
        if(previousHashLen != DIGEST_SIZE) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        
        // Finish computing the new auditSignatureHash
        mCBOREncoder.init(mTempBuffer, (short) 0, TEMP_BUFFER_SIZE);
        
        // responseHash : bstr
        short hashLen = mDigest.doFinal(mTempBuffer, (short) 0, (short) 0, mTempBuffer,
                mCBOREncoder.startByteString(DIGEST_SIZE));

        mECSignature.update(mTempBuffer, (short) 0, hashLen);
        
        // previousAuditSignatureHash : bstr
        // Compute new auditSignatureHash and append to output
        short signatureLen = mECSignature.sign(receiveBuffer, previousHashOffset, previousHashLen, mTempBuffer,
                hashLen);
 
        mCBOREncoder.init(outBuffer, (short) 0, mAPDUManager.getOutbufferLength());
        mCBOREncoder.startArray((short) 3);

        mCBOREncoder.encodeByteString(mTempBuffer, hashLen, signatureLen);
        mCBOREncoder.encodeByteString(mTempBuffer, (short) 0, hashLen);
        
        try {
            // Decrypt signing key
            signingKeyBlobLen = decryptCredentialData(receiveBuffer, signingKeyBlobOffset, signingKeyBlobLen,
                    mTempBuffer, TEMP_BUFFER_DOCTYPE_POS, mStatusWords[STATUS_DOCTYPE_LEN], mTempBuffer, hashLen);
    
            // Set the signing key
            ECPrivateKey signingKey = ((ECPrivateKey) mTempECKeyPair.getPrivate());
            signingKey.setS(mTempBuffer, hashLen, signingKeyBlobLen);
    
            // Sign the actual request (precomputed hash in digest object -> see above)
            mECSignature.init(signingKey, Signature.MODE_SIGN);
            signatureLen = mECSignature.signPreComputedHash(mTempBuffer, (short) 0, hashLen, mTempBuffer, (short) 0);
    
            mCBOREncoder.encodeByteString(mTempBuffer, (short) 0, signatureLen);
            
            mAPDUManager.setOutgoingLength(mCBOREncoder.getCurrentOffset());
        } catch (CryptoException e) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        } finally {
            ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_RETRIEVAL_STARTED, false);
            
            // Finished retrieval, reset the state so that future requests fail
            reset();
            mAccessControlManager.reset();
        }
    }
    
    /**
     * Verify only the authentication tag of an entry that did not encrypt data.  
     *    
     * @param authData Buffer with the authentication data
     * @param dataOffset Offset in the authentication data buffer
     * @param dataLength Length of the authentication data
     * @param tag Buffer of the provide authentication tag that should be tested
     * @param tagOffset Offset into the buffer for the authentication tag
     * @return True or false indicating if the authentication tag matches
     */
    public boolean verifyAuthenticationTag(byte[] authData, short dataOffset, short dataLength, byte[] tag, short tagOffset) {
        assertCredentialLoaded();

        CryptoBaseX.doFinal(mCredentialStorageKey, CryptoBaseX.ALG_AES_GCM, // Key information
                Cipher.MODE_ENCRYPT, mTempBuffer, (short) 0, (short) 0,  // No data input
                tag, tagOffset, AES_GCM_IV_SIZE, // IV
                authData, dataOffset, dataLength, 
                mTempBuffer, (short) 0, // Output location
                mTempBuffer, AES_GCM_IV_SIZE, // Tag output
                AES_GCM_TAG_SIZE);
        
        return Util.arrayCompare(mTempBuffer, AES_GCM_IV_SIZE, tag, (short)(tagOffset+AES_GCM_IV_SIZE), AES_GCM_TAG_SIZE) == 0;
    }

    /**
     * Verify the signature of the reader over the provided request data. Also
     * verifies that the ephemeral key is inside the requestData.
     */
    public boolean verifyReaderSignature(byte[] readerAuthData, short readerAuthDataOffset, short readerAuthDataLen,
            byte[] readerPubKey, short readerAuthPubKeyOffset, short readerAuthPubKeyLen, byte[] readerSignature,
            short readerSignOffset, short readerSignLen) {
        assertInitializedEphemeralKeys();
        boolean result = false;
        
        // Get the current ephemeral key
        ECPublicKey pubKey = ((ECPublicKey)mTempECKeyPair.getPublic());
        mStatusWords[STATUS_EPHKEY_LEN] = pubKey.getW(mTempBuffer, (short)0);
        
        try {
            // Set the reader public key and verify
            pubKey.setW(readerPubKey, readerAuthPubKeyOffset, readerAuthPubKeyLen);
            mECSignature.init(pubKey, Signature.MODE_VERIFY);

            result = mECSignature.verify(readerAuthData, readerAuthDataOffset, readerAuthDataLen, readerSignature,
                    readerSignOffset, readerSignLen);
        } catch(CryptoException e) {
            result = false;
        }
        // Reset the ephemeral key to the initial state
        pubKey.setW(mTempBuffer, (short) 0, mStatusWords[STATUS_EPHKEY_LEN]);
        return result;
    }

    /**
     * Compare the provided docType with the stored one. If they are equal, return
     * true. False otherwise.
     * 
     * @param docType       Buffer location for the docType to compare
     * @param docTypeOffset Offset in buffer
     * @param docTypeLen    Length of the given docType
     * @return Boolean indicating if the provided docType matches the stored one.
     */
    public boolean compareDocType(byte[] docType, short docTypeOffset, short docTypeLen) {
        if (docTypeLen == mStatusWords[STATUS_DOCTYPE_LEN]
                && Util.arrayCompare(docType, docTypeOffset, mTempBuffer, TEMP_BUFFER_DOCTYPE_POS, docTypeLen) == 0) {
            return true;
        }
        
        return false;
    }

    /**
     * Compare the provided ephemeral key with the stored one. If they are equal, return
     * true. False otherwise.
     * 
     * @param docType       Buffer location for the ephemeral key to compare
     * @param docTypeOffset Offset in buffer
     * @param docTypeLen    Length of the given ephemeral key
     * @return Boolean indicating if the provided ephemeral key matches the stored one.
     */
    public boolean compareEphemeralKey(byte[] ephKeyBuffer, short ephKeyOffset, short ephKeyLen) {
        // Get the current ephemeral key
        if (mStatusWords[STATUS_EPHKEY_LEN] == 0) {
            ECPublicKey pubKey = ((ECPublicKey) mTempECKeyPair.getPublic());
            mStatusWords[STATUS_EPHKEY_LEN] = pubKey.getW(mTempBuffer, (short) 0);
        }

        if (mStatusWords[STATUS_EPHKEY_LEN] == ephKeyLen && Util.arrayCompare(ephKeyBuffer, ephKeyOffset, mTempBuffer,
                (short) 0, mStatusWords[STATUS_EPHKEY_LEN]) == 0) {
            return true;
        }

        return false;
    }
    
    private void assertCredentialLoaded() {
        assertStatusFlagSet(FLAG_CREDENIAL_KEYS_INITIALIZED);
    }

    private void assertInPersonalizationState() {
        assertStatusFlagSet(FLAG_CREDENIAL_PERSONALIZATION_STATE);
    }
    private void assertStatusFlagSet(byte statusFlag) {
        if (!ICUtil.getBit(mStatusFlags, statusFlag)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }
    private void assertStatusFlagNotSet(byte statusFlag) {
        if (ICUtil.getBit(mStatusFlags, statusFlag)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    private void assertInitializedCredentialKeys() {
        if (!mCredentialECKeyPair.getPrivate().isInitialized()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }
    
    private void assertInitializedEphemeralKeys() {
        if (!mTempECKeyPair.getPublic().isInitialized() || !mTempECKeyPair.getPrivate().isInitialized()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }
}
