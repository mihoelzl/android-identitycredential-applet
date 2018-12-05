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

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacardx.apdu.ExtendedLength;

/**
 * @author michaelhoelzl
 *
 */
public class ICStoreApplet extends Applet implements ExtendedLength {

    public static final byte[] VERSION = { (byte) 0x00, (byte) 0x01, (byte) 0x01 };

    private APDUManager mAPDUManager;

    private CryptoManager mCryptoManager;
    
    private ICStoreApplet() {
        mAPDUManager = new APDUManager();
        
        mCryptoManager = new CryptoManager();
    }
    

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ICStoreApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    public void process(APDU apdu) {
        if (this.selectingApplet()) {
            mAPDUManager.reset();
            return;
        }

        if (!mAPDUManager.process(apdu)) {
            return;
        }

        byte[] buf = apdu.getBuffer();

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
            case (byte) ISO7816.INS_ICS_GET_VERSION:
                processGetVersion();
                break;

            case (byte) ISO7816.INS_ICS_ENCRYPT_ENTRIES:
                processEncryptEntries();
                break;
            case (byte) ISO7816.INS_ICS_GET_ENTRY:
                processGetEntry();
                break;
            case (byte) ISO7816.INS_ICS_TEST_CBOR:
                processTestCBOR();
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } 

        mAPDUManager.sendAll();
    }

    private void processEncryptEntries()
    //byte[] data, short dataOffset, short dataLength, byte[] outIVbuffer, byte outIVoffset, byte[] outTag, short outTagOffset, byte[] outBuffer, byte outBufferOffset) 
    {

//        
//        CryptoBaseX cipher = new CryptoBaseX();
//        
//        cipher.doFinal(key, CryptoBaseX.ALG_AES_GCM, Cipher.MODE_ENCRYPT, 
//                data, dataOffset, dataLength, 
//                ivBuffer, ivBufferOffset, ivBufferLength, 
//                authData, authDataOffset, authDataLength, 
//                outBuffer, outBufferOffset, 
//                outTag, outTagOffset, CryptoBaseX.AES_GCM_TAGLEN_128);
        
    }
    
    private void processTestCBOR() {        
        short receivingLength = mAPDUManager.receiveAll();
        byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();
        short inOffset = mAPDUManager.getOffsetCData();
        
        short le = mAPDUManager.setOutgoing();
        byte[] outBuffer = mAPDUManager.getSendBuffer();
        short outLength = 0;
        
        switch(CBORDecoder.readMajorType(receiveBuffer, inOffset)) {
        case CBORDecoder.TYPE_UNSIGNED_INTEGER:
        case CBORDecoder.TYPE_NEGATIVE_INTEGER:
            if(CBORDecoder.getIntegerSize(receiveBuffer, inOffset) == 1) {
                outBuffer[0] = CBORDecoder.readInt8(receiveBuffer, inOffset);
                outLength = 1;
            } else if(CBORDecoder.getIntegerSize(receiveBuffer, inOffset) == 2) {
                Util.setShort(outBuffer, (short) 0, CBORDecoder.readInt16(receiveBuffer, inOffset));
                outLength = 2;
            } 
            break;
        case CBORDecoder.TYPE_BYTE_STRING:
        case CBORDecoder.TYPE_TEXT_STRING:
            outLength = 2;
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

    private void processGetEntry() {
        
    }
    
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