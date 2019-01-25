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

/**
 * Abstract class for storing CBOR data in RAM as well as flash, where the flash
 * will only be used if RAM space is exceeded. The methods in this class help to
 * parse through the stored CBOR data in RAM and flash. The flash memory will
 * thereby be automatically copied into RAM for continuous processing. Note that
 * the RAM content will therefore be overwritten.
 */
public abstract class ExtendedCBORBuffer {

    protected static final byte RAM_READ_POS = 0;
    protected static final byte RAM_WRITE_POS = 1;
    protected static final byte FLASH_READ_POS = 2;
    protected static final byte FLASH_WRITE_POS = 3;
    protected static final byte STATUS_WORDS = 4;
    
    // Reference to a flash memory (potentially larger than RAM)
    protected final byte[] mFlashMemory;
    // Reference to a transient memory 
    protected final byte[] mRamMemory;
    
    protected final short[] mStatusWords;
    
    protected final CBORDecoder mCBORDecoder;
    
    protected ExtendedCBORBuffer(byte[] ramBuffer, byte[] flashBuffer, byte addStatusWords, CBORDecoder cborDecoder) {
        mRamMemory = ramBuffer;
        mFlashMemory = flashBuffer;
        mStatusWords = JCSystem.makeTransientShortArray((short) (STATUS_WORDS + addStatusWords), JCSystem.CLEAR_ON_DESELECT);
        
        mCBORDecoder = cborDecoder;
    }

    /**
     * Reset the internal state. All writing and reading positions will be forgotten.
     */
    public void reset() {
        ICUtil.shortArrayFillNonAtomic(mStatusWords, (short) 0, STATUS_WORDS, (short) 0);
    }

    /**
     * Store data into the internal RAM. If RAM is full, it will be written in flash memory. 
     * @param buffer Data that should be stored.
     * @param offset Offset into data buffer
     * @param len    Length of the data
     */
    public void storeData(byte[] buffer, short offset, short len) {
        short spaceInRam = (short) (mRamMemory.length - mStatusWords[RAM_WRITE_POS]);
        short storeInRam = len > spaceInRam ? spaceInRam : len;

        Util.arrayCopyNonAtomic(buffer, offset, mRamMemory, mStatusWords[RAM_WRITE_POS], storeInRam);

        mStatusWords[RAM_WRITE_POS] += storeInRam;

        // Remaining bytes
        len -= storeInRam;
        if ((short) (len + mStatusWords[FLASH_WRITE_POS]) > (short) (mFlashMemory.length)) {
            ISOException.throwIt(ISO7816.SW_INSUFFICIENT_MEMORY);
        }

        Util.arrayCopyNonAtomic(buffer, (short) (offset + storeInRam), mFlashMemory, mStatusWords[FLASH_WRITE_POS],
                len);

        mStatusWords[FLASH_WRITE_POS] += len;
    }
    
    /**
     * Reads data from flash to RAM and their current reading position. 
     */
    private void loadDataFromFlash() {
        // Check if end of flash storage or we load in a loop
        if (mStatusWords[FLASH_READ_POS] == mStatusWords[FLASH_WRITE_POS] || mStatusWords[RAM_READ_POS] == 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        short ramLen = (short) mRamMemory.length;
        short remainingLength = (short) (ramLen - mStatusWords[RAM_READ_POS]);
        short newDataLen = (short) (ramLen - remainingLength);

        // Do not read more data than available
        if ((short) (newDataLen + mStatusWords[FLASH_READ_POS]) > mStatusWords[FLASH_WRITE_POS]) {
            newDataLen = (short) (mStatusWords[FLASH_WRITE_POS] - mStatusWords[FLASH_READ_POS]);
        }

        Util.arrayCopyNonAtomic(mRamMemory, mStatusWords[RAM_READ_POS], mRamMemory, (short) 0, remainingLength);
        Util.arrayCopyNonAtomic(mFlashMemory, mStatusWords[FLASH_READ_POS], mRamMemory, remainingLength, newDataLen);
        
        mStatusWords[FLASH_READ_POS] += newDataLen;
        mStatusWords[RAM_READ_POS] = 0;
        mStatusWords[RAM_WRITE_POS] = (short) (remainingLength + newDataLen);

        mCBORDecoder.init(mRamMemory, (short) 0, mStatusWords[RAM_WRITE_POS]);
    }
    
    /**
     * Initialize the CBOR decoder and the current RAM reading position.
     */
    protected void initDecoder() {
        mCBORDecoder.init(mRamMemory, mStatusWords[RAM_READ_POS],
                (short) (mStatusWords[RAM_WRITE_POS] - mStatusWords[RAM_READ_POS]));
    }

    /**
     * Skip the current entry (loads data from flash if necessary).
     */
    protected void skipEntry() {
        try {
            mStatusWords[RAM_READ_POS] = mCBORDecoder.skipEntry();
        } catch (ISOException e) {
            if (e.getReason() == ISO7816.SW_WRONG_LENGTH) {
                loadDataFromFlash();
                skipEntry();
            } else {
                ISOException.throwIt(e.getReason());
            }
        }
    }
    
    /**
     * Read the length information at the current rading position (loads data from
     * flash if necessary).
     */
    protected short readLength(byte type) {
        short len = 0;
        try {
            len = mCBORDecoder.readMajorType(type);
            mStatusWords[RAM_READ_POS] = mCBORDecoder.getCurrentOffset();
        } catch (ISOException e) {
            if (e.getReason() == ISO7816.SW_WRONG_LENGTH) {
                loadDataFromFlash();
                return readLength(type);
            } else {
                ISOException.throwIt(e.getReason());
            }
        }
        return len;
    }
    
    /**
     * Checks if the provided string matches a text string at the current reading
     * position. Reading position will be increased to the next CBOR item.
     * 
     * @param string        Buffer into the string that should be used for
     *                      comparison
     * @param stringOffset  Offset of that string in the buffer
     * @param stringLen     Length of the string
     * @param currentkeyLen Length of the string in RAM at the current reading
     *                      position. Should be -1 if it is unknown (read directly
     *                      from the buffer)
     * @return Boolean indicating if the string was found. 
     */
    protected boolean matchesString(byte[] string, short stringOffset, short stringLen, short currentkeyLen) {
        // If keylen is not defined yet, read it from RAM
        currentkeyLen = (currentkeyLen == -1) ? readLength(CBORBase.TYPE_TEXT_STRING) : currentkeyLen;
        
        boolean success = false;
        try {
            if (currentkeyLen != stringLen) {
                mCBORDecoder.increaseOffset(currentkeyLen);
            } else if (Util.arrayCompare(mRamMemory, mCBORDecoder.getCurrentOffsetAndIncrease(currentkeyLen), string,
                    stringOffset, stringLen) == 0) {
                success = true;
            } 

            mStatusWords[RAM_READ_POS] = mCBORDecoder.getCurrentOffset();
        } catch (ISOException e) {
            if (e.getReason() == ISO7816.SW_WRONG_LENGTH) {
                loadDataFromFlash();
                return matchesString(string, stringOffset, stringLen, currentkeyLen);
            } else {
                ISOException.throwIt(e.getReason());
            }
        }
        return success;
    }
}
