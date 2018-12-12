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
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

public class CryptoManager {

    private static final short FLAG_TEST_CREDENTIAL = 0;
    private static final short FLAG_CREATED_EPHEMERAL_KEY = 1;
    private static final short FLAG_CREDENIAL_INITIALIZED = 2;
    private static final short STATUS_FLAGS_SIZE = 1;

    private static final short TEMP_BUFFER_SIZE = 128;
    
    private static final short AES_GCM_KEY_SIZE = 32;
    private static final short AES_GCM_IV_SIZE = 12;
    private static final short AES_GCM_TAG_SIZE = 16;
    private static final short EC_KEY_SIZE = 32;
    
    // Hardware bound key, initialized during Applet installation
    private AESKey mHBK;
    
    // Test key, initialized with only zeros during Applet installation
    private AESKey mTestKey;

    // Storage key for a credential
    private AESKey mCredentialStorageKey;

    // KeyPair for credential key generation and storage 
    private KeyPair mCredentialECKeyPair;

    // KeyPair for ephemeral key generation
    private KeyPair mEphemeralKeyPair;
    
    // Signature object for creating and verifying credential signatures 
    private Signature mECSignature;
    
    // Random data generator 
    private RandomData mRandomData;
    //TODO: implement my own counter based IV generator
    
    // Reference to the internal APDU manager instance
    private APDUManager mAPDUManager;
    
    // Reference to the internal CBOR decoder instance
    private CBORDecoder mCBORDecoder;
    
    // Reference to the internal CBOR encoder instance
    private CBOREncoder mCBOREncoder;

    // Temporary buffer for all cryptography operations
    private final byte[] mTempBuffer;
    
    // Temporary buffer in memory for status information
    private final byte[] mStatusFlags;


    public CryptoManager(APDUManager apduManager, CBORDecoder decoder, CBOREncoder encoder) {
        mTempBuffer = JCSystem.makeTransientByteArray((short)TEMP_BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
        mStatusFlags = JCSystem.makeTransientByteArray((short)STATUS_FLAGS_SIZE, JCSystem.CLEAR_ON_DESELECT);

        // Secure Random number generation for HBK
        mRandomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        mRandomData.generateData(mTempBuffer, (short)0, AES_GCM_KEY_SIZE);
        mHBK = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
        mHBK.setKey(mTempBuffer, (short)0);
        
        // Overwrite this new HBK key in the buffer and initialize a test key 
        Util.arrayFillNonAtomic(mTempBuffer, (short) 0, AES_GCM_KEY_SIZE, (byte) 0);
        mTestKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
        mTestKey.setKey(mTempBuffer, (short)0);

        // Create the storage key instance 
        mCredentialStorageKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256, false);
        
        // Configure key pair for elliptic curve key generation
        mCredentialECKeyPair = new KeyPair(
                (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false),
                (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT, KeyBuilder.LENGTH_EC_FP_256, false));
        
        mEphemeralKeyPair = new KeyPair(
                (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false),
                (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT, KeyBuilder.LENGTH_EC_FP_256, false));

        // At the moment we only support SEC-P256r1. Hence, can be configured at install time.
        Secp256r1.configureECKeyParameters((ECKey) mCredentialECKeyPair.getPrivate());
        Secp256r1.configureECKeyParameters((ECKey) mCredentialECKeyPair.getPublic());
        Secp256r1.configureECKeyParameters((ECKey) mEphemeralKeyPair.getPrivate());
        Secp256r1.configureECKeyParameters((ECKey) mEphemeralKeyPair.getPublic());

        // Initialize the object for signing data using EC
        mECSignature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        
        mAPDUManager = apduManager;
        mCBORDecoder = decoder;
        mCBOREncoder = encoder;
    }

    public void reset() {
        ICUtil.setBit(mStatusFlags, FLAG_TEST_CREDENTIAL, false);
        ICUtil.setBit(mStatusFlags, FLAG_CREATED_EPHEMERAL_KEY, false);
        ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_INITIALIZED, false);

        mCredentialStorageKey.clearKey();
    }
    
    public void process() {
        byte[] buf = mAPDUManager.getReceiveBuffer();
        switch(buf[ISO7816.OFFSET_INS]) {
        case ISO7816.INS_ICS_CREATE_EPHEMERAL_KEY:
            processCreateEphemeralKey();
            break;
        case ISO7816.INS_ICS_CREATE_CREDENTIAL:
            processCreateCredential();
            break;
        case ISO7816.INS_ICS_PERSONALIZE_ACCESS_CONTROL:
            processPersonalizeAccessControl();
            break;
        case ISO7816.INS_ICS_PERSONALIZE_ATTRIBUTE:
            processPersonalizeAccessControl();
            break;
        case ISO7816.INS_ICS_SIGN_PERSONALIZED_DATA:
            break;
        case ISO7816.INS_ICS_LOAD_CREDENTIAL_BLOB:
            processLoadCredentialBlob();
            break;
        case ISO7816.INS_ICS_CREATE_SIGNING_KEY:
            break;            
        default: 
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    /**
     * Process the CREATE EPHEMERAL KEY command
     */
    private void processCreateEphemeralKey() {
        mAPDUManager.receiveAll();
        byte[] buf = mAPDUManager.getReceiveBuffer();
                
        switch (Util.getShort(buf, ISO7816.OFFSET_P1)) {
        case 0: // Do nothing
            break;
        case 1: // EC_NIST_P_256            
            mAPDUManager.setOutgoing();
            
            // Create the ephemeral key
            mEphemeralKeyPair.genKeyPair();
            
            // Keep the ephemeral key in a separate buffer (required for reader authentication)
            short length = ((ECPublicKey)mEphemeralKeyPair.getPublic()).getW(mTempBuffer, (short) 0);

            // Start the CBOR encoding of the output 
            mCBOREncoder.init(mAPDUManager.getSendBuffer(), (short) 0, mAPDUManager.getOutbufferLength());
            short outLength = mCBOREncoder.startArray((short) 2);
            
            outLength += mCBOREncoder.encodeByteString(mTempBuffer, (short) 0, length);
            
            // Get the private key and append it to the output
            length = ((ECPrivateKey)mEphemeralKeyPair.getPrivate()).getS(mTempBuffer, (short)0);
            outLength += mCBOREncoder.encodeByteString(mTempBuffer, (short) 0, length);
            
            mAPDUManager.setOutgoingLength(outLength);

            ICUtil.setBit(mStatusFlags, FLAG_CREATED_EPHEMERAL_KEY, true);
            break;
        default: 
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    /**
     * Process the CREATE CREDENTIAL command. Outputs the encrypted credential blob
     */
    private void processCreateCredential() {        
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
        
        // Start encoding the output: credentialBlob = { "credentialData" : bstr }
        mCBOREncoder.init(outBuffer, (short) 0, mAPDUManager.getOutbufferLength());
        mCBOREncoder.startMap((short) 1);
        mCBOREncoder.encodeTextString(ICConstants.CBOR_MAPKEY_CREDENTIALDATA, (short)0, (short) ICConstants.CBOR_MAPKEY_CREDENTIALDATA.length); 

        short outOffset = mCBOREncoder.startByteString((short) (5 // CBOR structure with 5 bytes = 1 array start + 2 STK bstr + 2 CRK bstr   
                + AES_GCM_IV_SIZE
                + AES_GCM_KEY_SIZE + EC_KEY_SIZE + AES_GCM_TAG_SIZE));

        // Generate the AES-256 storage key 
        mRandomData.generateData(mTempBuffer, (short) 0, AES_GCM_KEY_SIZE);
        mCredentialStorageKey.setKey(mTempBuffer, (short) 0);

        // Create a new credential key
        mCredentialECKeyPair.genKeyPair();

        ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_INITIALIZED, true);
        
        // encrypt storage key and credential key for returning
        outOffset += wrapCredentialBlob(encryptionKey, outBuffer, outOffset);
        
        // Initialize the signature creation object
        mECSignature.init(mCredentialECKeyPair.getPrivate(), Signature.MODE_SIGN);
        
        // TODO: add CBOR structure for signature
        // Add credential type to the signature
        mECSignature.update(receiveBuffer, inOffset, receivingLength);
        
        mAPDUManager.setOutgoingLength(outOffset);
    }

    /**
     * Wrap the credential keys into an credential blob.
     * 
     * @param encryptionKey     The encryption that should be used.
     * @param outCredentialBlob Output buffer for the credentialBlob
     * @param outOffset         Offset in the buffer
     * @return Bytes written in the output buffer
     */
    private short wrapCredentialBlob(AESKey encryptionKey, byte[] outCredentialBlob, short outOffset) {
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
                Cipher.MODE_ENCRYPT, mTempBuffer, (short) 0, dataLength, // Data
                outCredentialBlob, outOffset, AES_GCM_IV_SIZE, // IV
                mTempBuffer, (short) 0, (short) 0, // authData empty
                outCredentialBlob, (short) (outOffset + AES_GCM_IV_SIZE), // Output location
                outCredentialBlob, (short) (outOffset + AES_GCM_IV_SIZE + dataLength), // Tag output
                CryptoBaseX.AES_GCM_TAGLEN_128) + AES_GCM_IV_SIZE + CryptoBaseX.AES_GCM_TAGLEN_128); 
    }

    /**
     * Process the LOAD CREDENTIAL command. Throws an exception if decryption is unsuccessful
     */
    private void processLoadCredentialBlob() {
        short receivingLength = mAPDUManager.receiveAll();
        byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();
        short inOffset = mAPDUManager.getOffsetIncomingData();
        
        AESKey encryptionKey = mHBK; 

        // Check if it is a test credential
        if(Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) == 0x1) { // Test credential
            ICUtil.setBit(mStatusFlags, FLAG_TEST_CREDENTIAL, true);

            encryptionKey = mTestKey;
        } else if(Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != 0x0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        
        try {
            if(receivingLength <= (short)(inOffset+AES_GCM_IV_SIZE+AES_GCM_TAG_SIZE)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);    
            }
            
            if(!unwrapCredentialBlob(encryptionKey, receiveBuffer, inOffset, receivingLength)) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
        } catch(CryptoException e) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }
    
    private boolean unwrapCredentialBlob(AESKey encryptionKey, byte[] credentialBlob, short offset, short length) throws CryptoException{
        short outLen = CryptoBaseX.doFinal(encryptionKey, CryptoBaseX.ALG_AES_GCM, Cipher.MODE_DECRYPT, // Key information
                credentialBlob, (short) (offset + AES_GCM_IV_SIZE), (short) (length - AES_GCM_IV_SIZE - CryptoBaseX.AES_GCM_TAGLEN_128), // Data
                credentialBlob, offset, AES_GCM_IV_SIZE, // IV
                mTempBuffer, (short) 0, (short) 0, // authData empty
                mTempBuffer, (short) 0, // Output location
                credentialBlob, (short) (offset + length - CryptoBaseX.AES_GCM_TAGLEN_128), // Tag input
                CryptoBaseX.AES_GCM_TAGLEN_128); 
        
        mCBORDecoder.init(mTempBuffer, (short) 0, outLen);
        if(mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY) == 2) {
            if(mCBORDecoder.readMajorType(CBORBase.TYPE_BYTE_STRING) != -1) {
                short len = mCBORDecoder.readLength();
                
                if (len == AES_GCM_KEY_SIZE) {
                    mCredentialStorageKey.setKey(mTempBuffer, mCBORDecoder.getCurrentOffsetAndIncrease(len));
                    len = mCBORDecoder.readLength();
                    
                    if (len == EC_KEY_SIZE) {
                        ((ECPrivateKey)mCredentialECKeyPair.getPrivate()).setS(mTempBuffer, mCBORDecoder.getCurrentOffsetAndIncrease(len), len);

                        ICUtil.setBit(mStatusFlags, FLAG_CREDENIAL_INITIALIZED, true);
                        return true;
                    }
                }
            }
        }
        return false;
    }
    
    public short createCredentialCertificate(byte[] outCertificateBuffer, short outOffset) {
        assertCredentialLoaded();
        
        return 0;
    }
    
    /**
     * Process the PERSONALIZE ACCESS CONTROL command. Throws an exception if received CBOR structure is invalid.
     */
    private void processPersonalizeAccessControl() {
        assertCredentialLoaded();
        
        short receivingLength = mAPDUManager.receiveAll();
        byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();
        short inOffset = mAPDUManager.getOffsetIncomingData();

        mAPDUManager.setOutgoing();
        byte[] outBuffer = mAPDUManager.getSendBuffer();

        mCBORDecoder.init(receiveBuffer, inOffset, receivingLength);
        mCBOREncoder.init(outBuffer, (short) 0, mAPDUManager.getOutbufferLength());

        short nrOfProfiles = 0;
        
        if((nrOfProfiles = mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY)) < 0) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        
        short outLength = mCBOREncoder.startArray(nrOfProfiles);
        short profileLength = 0;
        short encodedLocation = 0;
        
        for(short i=0; i<nrOfProfiles; i++) {
            profileLength = mCBORDecoder.readMajorType(CBORBase.TYPE_BYTE_STRING);
            encodedLocation = mCBOREncoder.startByteString(profileLength);

            outLength += encryptCredentialData(mTempBuffer, (short) 0, (short) 0,  // No data input
                    receiveBuffer, mCBORDecoder.getCurrentOffsetAndIncrease(profileLength), profileLength, // Profile as auth data 
                    outBuffer, encodedLocation); // Output data
        }

        mAPDUManager.setOutgoingLength(outLength);
        
        // TODO: signature creation
    }
    
    /**
     * Encrypt the given data with the storage key using AES-GCM. The data output format is R || encrypted data || Tag.
     * 
     * @param data Input data that should be encrypted
     * @param offset Offset in buffer
     * @param length Length of data
     * @param authData Authentication data 
     * @param authDataOffset Offset of authentication data in buffer
     * @param authLen Length of authentication data
     * @param outBuffer Output buffer
     * @param outOffset Offset in output buffer
     * 
     * @return Number of bytes written to output buffer
     */
    public short encryptCredentialData(byte[] data, short offset, short length, byte[] authData, short authDataOffset, short authLen, byte[] outBuffer, short outOffset) {
        assertCredentialLoaded();
        
        // Generate the IV
        mRandomData.generateData(outBuffer, (short) outOffset, (short) AES_GCM_IV_SIZE);
        
        return (short) (CryptoBaseX.doFinal(mCredentialStorageKey, CryptoBaseX.ALG_AES_GCM, // Key information
                Cipher.MODE_ENCRYPT, data, offset, length, // Data
                outBuffer, outOffset, AES_GCM_IV_SIZE, // IV
                authData, authDataOffset, authLen, // authData empty
                outBuffer, (short) (outOffset + AES_GCM_IV_SIZE), // Output location
                outBuffer, (short) (outOffset + AES_GCM_IV_SIZE + length), // Tag output
                CryptoBaseX.AES_GCM_TAGLEN_128) + AES_GCM_IV_SIZE + CryptoBaseX.AES_GCM_TAGLEN_128);
    }
    
    /**
     * Decrypt the given data with the storage key using AES-GCM. The input format for data has to be R || encrypted data || Tag.
     * 
     * @param encryptedData Input data that should be decrypted
     * @param offset Offset in buffer
     * @param length Length of data
     * @param authData Authentication data 
     * @param authDataOffset Offset of authentication data in buffer
     * @param authLen Length of authentication data
     * @param outBuffer Output buffer for decrypted data
     * @param outOffset Offset in output buffer
     * @return Number of bytes written to output buffer
     */
    public short decryptCredentialData(byte[] encryptedData, short offset, short length, byte[] authData, short authDataOffset, short authLen, byte[] outData, short outOffset) {
        assertCredentialLoaded();
        
        return (short) (CryptoBaseX.doFinal(mCredentialStorageKey, CryptoBaseX.ALG_AES_GCM, Cipher.MODE_DECRYPT, // Key information
                encryptedData, (short) (offset + AES_GCM_IV_SIZE), (short) (length - AES_GCM_IV_SIZE - CryptoBaseX.AES_GCM_TAGLEN_128), // Data
                encryptedData, offset, AES_GCM_IV_SIZE, // IV
                authData, authDataOffset, authLen, // authData 
                outData, outOffset, // Output location
                encryptedData, (short) (offset + length - CryptoBaseX.AES_GCM_TAGLEN_128), // Tag location
                CryptoBaseX.AES_GCM_TAGLEN_128)); 
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

    private void assertCredentialLoaded() {
        if (!ICUtil.getBit(mStatusFlags, FLAG_CREDENIAL_INITIALIZED)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }
    
    private void assertInitializedCredentialKeys() {
        if (!mCredentialECKeyPair.getPublic().isInitialized() || !mCredentialECKeyPair.getPrivate().isInitialized()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }
    
    private void assertInitializedEphemeralKeys() {
        if (!mEphemeralKeyPair.getPublic().isInitialized() || !mEphemeralKeyPair.getPrivate().isInitialized()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }
}
