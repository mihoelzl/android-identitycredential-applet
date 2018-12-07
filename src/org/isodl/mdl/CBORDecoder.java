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
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class CBORDecoder {

    // Mask for the major CBOR type
    private static final byte MAJOR_TYPE_MASK = (byte) 0xE0;

    // Mask for additional information in the low-order 5 bits 
    private static final byte ADDINFO_MASK = (byte) 0x1F;
    
    // Major type 0: an unsigned integer
    public static final byte TYPE_UNSIGNED_INTEGER = (byte) (0x00);
    // Major type 1: a negative integer
    public static final byte TYPE_NEGATIVE_INTEGER = (byte) (0x01);
    // Major type 2: a byte string
    public static final byte TYPE_BYTE_STRING = (byte) (0x02);
    // Major type 3: a text string
    public static final byte TYPE_TEXT_STRING = (byte) (0x03);
    // Major type 4: an array of data items
    public static final byte TYPE_ARRAY = (byte) (0x04);
    // Major type 5: a map of pairs of data items
    public static final byte TYPE_MAP = (byte) (0x05);
    // Major type 6: optional semantic tagging of other major types
    public static final byte TYPE_TAG = (byte) (0x06);
    // Major type 7: floating-point numbers
    public static final byte TYPE_FLOAT = (byte) (0x07);
    
    /** 
     * Length information (Integer size, array length, etc.) in low-order 5 bits
     */
    // One byte unsigned value (uint8)
    private static final byte ONE_BYTE = 0x18;
    // Two byte unsigned value (uint16)
    private static final byte TWO_BYTES = 0x19;
    // Four byte unsigned value (uint32)
    private static final byte FOUR_BYTES = 0x1a;
    // Eight byte unsigned value (uint64)
    private static final byte EIGHT_BYTES = 0x1b;

    /** 
     * Values for additional information in major type 7
     */
    // CBOR encoded boolean - false
    private static final byte FALSE = (byte) 0xF4;
    // CBOR encoded boolean - true
    private static final byte TRUE = (byte) 0xF5;
    // CBOR encoded null
    private static final byte NULL = (byte) 0xF6;
    // CBOR encoded undefined value
    private static final byte UNDEFINED = (byte) 0xF7;
    
    // CBOR encoded break for unlimited arrays/maps.
    private static final byte BREAK = (byte) 0xFF;

    public static final byte INVALID_INPUT = -1;

    private short[] mStatusWords;
    
    private byte[] mBuffer;
    
    public CBORDecoder() {
        mStatusWords = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_RESET);     
    }
    
    /**
     * Initializes with a given array and the given offset.
     * @param buffer Buffer with CBOR content
     * @param offset Offset in buffer where content should be read/written
     */
    public void init(byte[] buffer, short off) {
        mBuffer = buffer;
        mStatusWords[0] = off;
    }

    /**
     * Reset the internal state of the parser 
     */
    public void reset() {
        mBuffer = null;
        mStatusWords[0] = 0;
    }

    /**
     * Return the current major type (does not increase buffer location)
     * 
     * @return Major type at the current buffer location
     */
    public byte getMajorType() {
        return (byte) ((mBuffer[mStatusWords[0]] & MAJOR_TYPE_MASK) >> 5);
    }

    /**
     * Returns the size of the integer at the current location
     * 
     * @return Size of the integer in bytes
     */
    public byte getIntegerSize() {         
        byte eventlength = (byte) (mBuffer[mStatusWords[0]] & ADDINFO_MASK);
        if(eventlength <= ONE_BYTE) {
            return 1;
        } else if(eventlength == TWO_BYTES) {
            return 2;
        } else if(eventlength == FOUR_BYTES) {
            return 4;
        } else if(eventlength == EIGHT_BYTES) {
            return 8;
        }
        return INVALID_INPUT;
    }

    /**
     * Returns the current offset in the buffer stream and increases the offset by
     * the given number
     * 
     * @param inc Value to add to the offset
     * @return Current offset value (before increase)
     */
    private short getOffsetAndIncrease(short inc) {
        short off = mStatusWords[0];
        mStatusWords[0]+=inc;
        return off;
    }
    
    /**
     * Read the raw byte at the current buffer location and increase the offset by one.
     * @return Current raw byte
     */
    private byte readRawByte() {
        return mBuffer[mStatusWords[0]++];
    }

    /**
     * Read the 8bit integer at the current location (offset will be increased)
     * 
     * @return The current 8bit Integer
     */
    public byte readInt8() {
        byte eventlength = (byte) (readRawByte() & ADDINFO_MASK);
        if(eventlength < ONE_BYTE) {
            return eventlength;  
        } else if(eventlength == ONE_BYTE) {
            return (byte)(readRawByte() & 0xff);              
        } else {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        return 0;
    }


    /**
     * Read the 16bit integer at the current location (offset will be increased)
     * 
     * @return The current 16bit Integer
     */
    public short readInt16() {
        byte addInfo = (byte) (readRawByte() & ADDINFO_MASK);
        if(addInfo == TWO_BYTES) {
            return Util.getShort(mBuffer, getOffsetAndIncrease((short) 2));  
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
    
    public short readValueAsArray(byte[] outBuffer, short outOffset) {

        return 0;
    }
}
