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

package android.security.identity_credential;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacardx.apdu.ExtendedLength;

public class ICStoreApplet extends Applet implements ExtendedLength {

    // Version identifier of this Applet
    public static final byte[] VERSION = { (byte) 0x00, (byte) 0x01, (byte) 0x03 };

    private final APDUManager mAPDUManager;

    private final CryptoManager mCryptoManager;
    
    private final CBORDecoder mCBORDecoder;

    private final CBOREncoder mCBOREncoder;
    
    private ICStoreApplet() {
        mCBORDecoder = new CBORDecoder();
        
        mCBOREncoder = new CBOREncoder();
        
        mAPDUManager = new APDUManager();

        mCryptoManager = new CryptoManager(mAPDUManager, mCBORDecoder, mCBOREncoder);
    }
    

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ICStoreApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    public void process(APDU apdu) {
        byte[] buf = apdu.getBuffer();

        if (!mAPDUManager.process(apdu)) {
            return;
        }

        if (this.selectingApplet()) {
            mCryptoManager.reset();
            processSelectApplet(apdu);
            return;
        }


        if (apdu.isISOInterindustryCLA()) {
            switch (buf[ISO7816.OFFSET_INS]) {
            // TODO: In future we might want to support standard ISO operations (select, get
            // data, etc.).

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                break;
            }
        } else {
            switch (buf[ISO7816.OFFSET_INS]) {
            case ISO7816.INS_ICS_GET_VERSION:
                processGetVersion();
                break;
            case ISO7816.INS_ICS_CREATE_CREDENTIAL:
            case ISO7816.INS_ICS_CREATE_SIGNING_KEY:
            case ISO7816.INS_ICS_CREATE_EPHEMERAL_KEY:
            case ISO7816.INS_ICS_PERSONALIZE_ACCESS_CONTROL:
            case ISO7816.INS_ICS_PERSONALIZE_ATTRIBUTE:
            case ISO7816.INS_ICS_SIGN_PERSONALIZED_DATA:
            case ISO7816.INS_ICS_LOAD_CREDENTIAL_BLOB:
            case ISO7816.INS_ICS_GET_ATTESTATION_CERT:
                mCryptoManager.process();
                break;
            case ISO7816.INS_ICS_AUTHENTICATE:
                processAuthenticate();
            case ISO7816.INS_ICS_GET_ENTRY:
                processGetEntry();
                break;
            case ISO7816.INS_ICS_CREATE_SIGNATURE:
                break;
            case ISO7816.INS_ICS_TEST_CBOR:
                processTestCBOR();
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } 

        mAPDUManager.sendAll();
    }

    private void processTestCBOR() {
        short receivingLength = mAPDUManager.receiveAll();
        byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();
        short inOffset = mAPDUManager.getOffsetIncomingData();
        
        short le = mAPDUManager.setOutgoing(true);
        byte[] outBuffer = mAPDUManager.getSendBuffer();
        short outLength = 0;

        mCBORDecoder.init(receiveBuffer, inOffset, receivingLength);
        mCBOREncoder.init(outBuffer, (short) 0, mAPDUManager.getOutbufferLength());
        
        byte negInt = 0;
        
        switch(mCBORDecoder.getMajorType()) {
        case CBORDecoder.TYPE_NEGATIVE_INTEGER:
            negInt = 1;  
            break; // CBOR encoding of negative integers not supported
        case CBORDecoder.TYPE_UNSIGNED_INTEGER:
            byte intSize = mCBORDecoder.getIntegerSize();
            if(intSize  == 1) {
                outLength = mCBOREncoder.encodeUInt8(mCBORDecoder.readInt8());
            } else if(intSize == 2) {
                outLength = mCBOREncoder.encodeUInt16(mCBORDecoder.readInt16());
//            } else if(intSize == 4) {
//                JCint.setInt(outBuffer, (short) 0, CBORDecoder.readInt32(receiveBuffer, inOffset));
//                outLength = 4;
            } 
            break;

        case CBORDecoder.TYPE_TEXT_STRING:
            short len = mCBORDecoder.readLength();
            short byteArrayOffset = mCBORDecoder.getCurrentOffsetAndIncrease(len);
            outLength = mCBOREncoder.encodeTextString(receiveBuffer, byteArrayOffset, len);
            break;
        case CBORDecoder.TYPE_BYTE_STRING:
            len = mCBORDecoder.readLength();
            byteArrayOffset = mCBORDecoder.getCurrentOffsetAndIncrease(len);
            outLength = mCBOREncoder.encodeByteString(receiveBuffer, byteArrayOffset, len);
            break;
        case CBORDecoder.TYPE_ARRAY:
            outLength = 2;
            break;
        case CBORDecoder.TYPE_MAP:
            outLength = 2;
            break;
        case CBORDecoder.TYPE_TAG:
            outLength = 2;
            break;
        case CBORDecoder.TYPE_FLOAT:
            outLength = 2;
            break;
            
        }
        
        mAPDUManager.setOutgoingLength(outLength);
    }

    /**
     * Process the select command and return hardware configuration in the select
     * applet command.
     */
    private void processSelectApplet(APDU apdu){
        mAPDUManager.setOutgoing();
        byte[] outBuff = mAPDUManager.getSendBuffer();
        Util.setShort(outBuff, (short)0, (short) apdu.getBuffer().length);
        Util.setShort(outBuff, (short)2, APDUManager.MAXCHUNKSIZE);
        Util.setShort(outBuff, (short)4, mCryptoManager.getAESKeySize());

        mAPDUManager.setOutgoingLength((short) 6);
        mAPDUManager.sendAll();
    }
    
    
    /**
     * Process the AUTHENTICATE command (validate encrypted access control profiles)
     */
    private void processAuthenticate() {
        short receivingLength = mAPDUManager.receiveAll();
        byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();
        short inOffset = mAPDUManager.getOffsetIncomingData();
        
        short p1p2 =Util.getShort(receiveBuffer, ISO7816.OFFSET_P1);
        
        if(p1p2 == 0x0) { // No authentication, just 
            
        } else if(p1p2 == 0x1) { // Reader authentication

        } else if (p1p2 == 0x2) { // User authentication
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        }
    }

    private void processLoadAccessControlProfile() {
        short receivingLength = mAPDUManager.receiveAll();
        byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();
        short inOffset = mAPDUManager.getOffsetIncomingData();
        
        if (Util.getShort(receiveBuffer, ISO7816.OFFSET_P1) != 0x0) { 
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        
        mAPDUManager.setOutgoing();

        mCBORDecoder.init(receivingLength, receivingLength);
        
        if(mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY) == 2) {
            
        }
    }
    
    private void processGetEntry() {
        
    }
    
    /**
     * Process the GET VERSION command and return the currrent applet version
     */
    private void processGetVersion() {
        final byte[] inBuffer = APDU.getCurrentAPDUBuffer();

        if (Util.getShort(inBuffer, ISO7816.OFFSET_P1) != 0x0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        short le = mAPDUManager.setOutgoing();
        final byte[] outBuffer = mAPDUManager.getSendBuffer();

        if (le < (short) VERSION.length) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short outLength = 0;
        try {
            outLength = Util.arrayCopyNonAtomic(VERSION, (short) 0, outBuffer, outLength, (short) VERSION.length);
        } catch (ArrayIndexOutOfBoundsException e) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        mAPDUManager.setOutgoingLength(outLength);
    }
    
}