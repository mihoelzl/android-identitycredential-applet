/**
 * 
 */
package org.isodl.mdl;

import com.nxp.id.jcopx.security.CipherX;
import com.nxp.id.jcopx.security.CryptoBaseX;
import com.nxp.id.jcopx.security.KeyAgreementX;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacardx.crypto.Cipher;

/**
 * @author michaelhoelzl
 *
 */
public class ICStoreApplet extends Applet {

    public static final byte[] VERSION = { (byte) 0x00, (byte) 0x01, (byte) 0x01 };
    public final static byte ICStore_CLA = (byte) 0xB0;

    private APDUManager mSecurityManager;

    private AESKey key;
    
    private ICStoreApplet() {
        mSecurityManager = new APDUManager();
        
        key = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
                KeyBuilder.LENGTH_AES_128,
                false);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ICStoreApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    public void process(APDU apdu) {
        if (this.selectingApplet()) {
            mSecurityManager.reset();
            return;
        }

        if (!mSecurityManager.process(apdu)) {
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
            case (byte) ISO7816.INS_ICS_TEST:
                processTestCBOR();
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } 

        mSecurityManager.sendAll();
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
        CBORDecoder cborDecoder = new CBORDecoder();
        
        short receivingLength = mSecurityManager.receiveAll();
        byte[] receiveBuffer = mSecurityManager.getReceiveBuffer();
        
        short le = mSecurityManager.setOutgoing();
        byte[] outBuffer = mSecurityManager.getSendBuffer();
                
        short pos = mSecurityManager.getOffsetCData();
        byte event = CBORDecoder.EVENT_NEED_MORE_INPUT;
        
        while (event != CBORDecoder.EVENT_EOF){
            while ((event = cborDecoder.nextEvent()) == CBORDecoder.EVENT_NEED_MORE_INPUT) {
                pos += cborDecoder.feed(receiveBuffer, pos, (short) (receivingLength-pos));

                if (pos == receivingLength) {
                    cborDecoder.finish();
                }
            }

            if (event == CBORDecoder.EVENT_ERROR) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            if (event == CBORDecoder.EVENT_VALUE_INT16) {
                short val = cborDecoder.getCurrentShort();
                Util.setShort(outBuffer, (short) 0, val);
            }
        } 
        mSecurityManager.setOutgoingLength((short)2);
    }

    private void processGetEntry() {
        
    }
    
    private void processGetVersion() {
        final byte[] inBuffer = APDU.getCurrentAPDUBuffer();

        if ((inBuffer[ISO7816.OFFSET_P1] != 0) || (inBuffer[ISO7816.OFFSET_P2] != 0)) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        short le = mSecurityManager.setOutgoing();
        final byte[] outBuffer = mSecurityManager.getSendBuffer();

        if (le < (short) VERSION.length) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short outLength = 0;
        try {
            outLength = Util.arrayCopyNonAtomic(VERSION, (short) 0, outBuffer, outLength, (short) VERSION.length);
        } catch (ArrayIndexOutOfBoundsException e) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        mSecurityManager.setOutgoingLength(outLength);
    }
}