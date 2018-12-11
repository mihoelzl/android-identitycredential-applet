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

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class CBORDecoder extends CBORBase{

    /**
     * Return the current major type (does not increase buffer location)
     * 
     * @return Major type at the current buffer location
     */
    public byte getMajorType() {
        return (byte) ((mBuffer[mStatusWords[0]] & MAJOR_TYPE_MASK) >> 5);
    }

    /**
     * Returns the size of the integer at the current location.
     * 
     * @return Size of the integer in bytes
     */
    public byte getIntegerSize() {         
        final byte eventlength = (byte) (mBuffer[mStatusWords[0]] & ADDINFO_MASK);
        if(eventlength <= ENCODED_ONE_BYTE) {
            return 1;
        } else if(eventlength == ENCODED_TWO_BYTES) {
            return 2;
        } else if(eventlength == ENCODED_FOUR_BYTES) {
            return 4;
        } else if(eventlength == ENCODED_EIGHT_BYTES) {
            return 8;
        }
        return INVALID_INPUT;
    }

    /**
     * Read the 8bit integer at the current location (offset will be increased).
     * Note: this function works for positive and negative integers. Sign
     * interpretation needs to be done by the caller.
     * 
     * @return The current 8bit Integer
     */
    public byte readInt8() {
        final byte eventlength = (byte) (readRawByte() & ADDINFO_MASK);
        if(eventlength < ENCODED_ONE_BYTE) {
            return eventlength;  
        } else if(eventlength == ENCODED_ONE_BYTE) {
            return (byte)(readRawByte() & 0xff);              
        } else {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        return 0;
    }


    /**
     * Read the 16bit integer at the current location (offset will be increased)
     * Note: this function works for positive and negative integers. Sign
     * interpretation needs to be done by the caller.
     * 
     * @return The current 16bit Integer
     */
    public short readInt16() {
        final byte addInfo = (byte) (readRawByte() & ADDINFO_MASK);
        if(addInfo == ENCODED_TWO_BYTES) {
            return Util.getShort(mBuffer, getCurrentOffsetAndIncrease((short) 2));  
        } else { 
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        return 0;
    }
    
//    public static int readInt32(byte[] cborInput, short offset) {
//        byte addInfo = (byte) (cborInput[offset] & ADDINFO_MASK);
//        if(addInfo == FOUR_BYTES) {
//            return JCint.getInt(cborInput, (short) (offset+1));  
//        } 
//        return -1;
//    }

    public short readLength() {
        final byte size = getIntegerSize(); // Read length information
        short length = 0;
        if (size == 1) {
            length = readInt8();
        } else if (size == 2) {
            length = readInt16();
        } else { // length information above 4 bytes not supported
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        return length;
    }
        
    /**
     * Read a byte string at the current location and copy it into the given buffer
     * (offset will be increased).
     * 
     * @param outBuffer Buffer where the array should be copied to
     * @param outOffset Offset location within the buffer
     * @return Number of bytes copied into the buffer
     */
    public short readByteString(byte[] outBuffer, short outOffset) {
        short length = readLength();
        return readRawByteArray(outBuffer, outOffset, length);
    }
    
    /**
     * Read the byte array at the current location and copy it into the given buffer
     * (offset will be increased).
     * 
     * @param outBuffer Buffer where the array should be copied to
     * @param outOffset Offset location within the buffer
     * @param length Number of bytes that should be read from the buffer
     * @return Number of bytes copied into the buffer
     */
    private short readRawByteArray(byte[] outBuffer, short outOffset, short length) {
        if(length > (short) outBuffer.length || (short)(length + getCurrentOffset()) > getBufferLength())
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
        length = Util.arrayCopyNonAtomic(mBuffer, getCurrentOffset(), outBuffer, outOffset, length);
        increaseOffset(length);
        
        return length;
    }


    /**
     * Read the raw byte at the current buffer location and increase the offset by one.
     * @return Current raw byte
     */
    private byte readRawByte() {
        return mBuffer[mStatusWords[0]++];
    }
}
