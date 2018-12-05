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
import javacardx.framework.math.BigNumber;
import javacardx.framework.util.intx.JCint;

public class CBORDecoder {

    private static final byte MAJOR_TYPE_MASK = (byte) 0xE0;
    
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

    // Mask for additional information in the low-order 5 bits 
    private static final byte ADDINFO_MASK = (byte) 0x1F;
    
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

    /**
     * Returns the current major type
     * 
     * @return
     */
    public static byte readMajorType(byte[] cborInput, short offset) {
        if ((short)cborInput.length <= offset) {
            return INVALID_INPUT;
        }
        return (byte) ((cborInput[offset] & MAJOR_TYPE_MASK) >> 5);
    }

    public static byte readInt8(byte[] cborInput, short offset) {
        if ((short)cborInput.length <= offset) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        byte eventlength = (byte) (cborInput[offset] & ADDINFO_MASK);
        if(eventlength < ONE_BYTE) {
            return eventlength;  
        } else if(eventlength == ONE_BYTE) {
            return (byte)(cborInput[(short)(offset+1)] & 0xff);              
        } else {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        return 0;
    }

    public static short readInt16(byte[] cborInput, short offset) {
        if ((short)cborInput.length <= offset) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        byte addInfo = (byte) (cborInput[offset] & ADDINFO_MASK);
        if(addInfo == TWO_BYTES) {
            return Util.getShort(cborInput, (short) (offset+1));  
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

    public static byte getIntegerSize(byte[] cborInput, short offset) {
        if ((short)cborInput.length <= offset) {
            return INVALID_INPUT;
        }
         
        byte eventlength = (byte) (cborInput[offset] & ADDINFO_MASK);
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
    
    public static short getCurrentValueAsArray(byte[] cborInput, short offset, byte[] outBuffer, short outOffset) {

        return 0;
    }
}
