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

import javacard.framework.Util;
import javacardx.framework.math.BigNumber;

public class CBORDecoder {

    static final byte MAJOR_TYPE_MASK = (byte) 0xE0;
    
    // Major type 0: an unsigned integer
    static final byte TYPE_UNSIGNED_INTEGER = (byte) (0x00);
    // Major type 1: a negative integer
    static final byte TYPE_NEGATIVE_INTEGER = (byte) (0x01);
    // Major type 2: a byte string
    static final byte TYPE_BYTE_STRING = (byte) (0x02);
    // Major type 3: a text string
    static final byte TYPE_TEXT_STRING = (byte) (0x03);
    // Major type 4: an array of data items
    static final byte TYPE_ARRAY = (byte) (0x04);
    // Major type 5: a map of pairs of data items
    static final byte TYPE_MAP = (byte) (0x05);
    // Major type 6: optional semantic tagging of other major types
    static final byte TYPE_TAG = (byte) (0x06);
    // Major type 7: floating-point numbers
    static final byte TYPE_FLOAT = (byte) (0x07);

    // Mask for additional information in the low-order 5 bits 
    static final byte ADDINFO_MASK = (byte) 0x1F;
    
    /** 
     * Length information in low-order 5 bits
     */
    // One byte unsigned value (uint8)
    static final byte ONE_BYTE = 0x18;
    // Two byte unsigned value (uint16)
    static final byte TWO_BYTES = 0x19;
    // Four byte unsigned value (uint32)
    static final byte FOUR_BYTES = 0x1a;
    // Eight byte unsigned value (uint64)
    static final byte EIGHT_BYTES = 0x1b;

    /** 
     * Values for additional information in major type 7
     */
    // CBOR encoded boolean - false
    static final byte FALSE = (byte) 0xF4;
    // CBOR encoded boolean - true
    static final byte TRUE = (byte) 0xF5;
    // CBOR encoded null
    static final byte NULL = (byte) 0xF6;
    // CBOR encoded undefined value
    static final byte UNDEFINED = (byte) 0xF7;
    
    // CBOR encoded break for unlimited arrays/maps.
    static final byte BREAK = (byte) 0xFF;
    
    public static final byte EVENT_ERROR = (byte) 0x00;
    public static final byte EVENT_EOF = (byte) 0xFF;

    public static final byte EVENT_NEED_MORE_INPUT = (byte) 0x01;


    /**
     * Returns the current major type
     * 
     * @return
     */
    public static byte readMajorType(byte[] cborInput, short offset) {
        return (byte) ((cborInput[offset] & MAJOR_TYPE_MASK) >> 5);
    }

    public static byte readInt8(byte[] cborInput, short offset) {
        byte eventlength = (byte) (cborInput[offset] & ADDINFO_MASK);
        if(eventlength < ONE_BYTE) {
            return eventlength;  
        } else if(eventlength == ONE_BYTE) {
            return (byte)(cborInput[(short)(offset+1)] & 0xff);              
        }
        return -1;
    }

    public static short readInt16(byte[] cborInput, short offset) {
        byte addInfo = (byte) (cborInput[offset] & ADDINFO_MASK);
        if(addInfo == TWO_BYTES) {
            return Util.getShort(cborInput, (short) (offset+1));  
        } 
        return -1;
    }

    public static byte getIntegerSize(byte[] cborInput, short offset) {
        byte eventlength = (byte) (cborInput[offset] & ADDINFO_MASK);
        if(eventlength < ONE_BYTE) {
            return 1;
        } else {
            switch(eventlength) {
            case ONE_BYTE:
                return 1;
            case TWO_BYTES:
                return 2;
            case FOUR_BYTES:
                return 4;
            case EIGHT_BYTES:
                return 8;
            default:   
                return -1;
            } 
        }
    }
    
    public static short getCurrentValueAsArray(byte[] cborInput, short offset, byte[] outBuffer, short outOffset) {

        return 0;
    }
}
