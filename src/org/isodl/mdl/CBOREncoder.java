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

public class CBOREncoder extends CBORBase{

    /**
     * Start a new array at the current buffer location with the given array size.
     */
    public void encodeArrayStart(short arraySize) {
        encodeValue((byte) (TYPE_ARRAY << 5), arraySize);
    }

    /**
     * Start a new map at the current buffer location with the given map size.
     */
    public void encodeMapStart(short mapSize) {
        encodeValue((byte) (TYPE_MAP << 5), mapSize);
    }
    
    /**
     * Encodes a byte string with the given length at the current buffer location.
     * The actual byte string is not copied into the buffer. Returns the offset in
     * the buffer where the byte string is supposed to be copied into. The offset
     * will afterwards be increased by the given length
     */
    public short encodeByteString(short length) {
        encodeValue((byte) (TYPE_BYTE_STRING << 5), length);
        return getCurrentOffsetAndIncrease(length);
    }

    /**
     * Encodes the given byte string at the current buffer location.
     */
    public short encodeByteString(byte[] byteString, short offset, short length) {
        encodeValue((byte) (TYPE_BYTE_STRING << 5), length);
        return writeRawByteArray(byteString, offset, length);
    }
    
    /**
     * Encodes the given byte string at the current buffer location.
     */
    public short encodeTextString(byte[] byteString, short offset, short length) {
        encodeValue((byte) (TYPE_TEXT_STRING << 5), length);
        return writeRawByteArray(byteString, offset, length);
    }
    
    /**
     * Encode the given integer value at the current buffer location.
     * 
     * @param value Value to encode in the byte array. Note: as there are no
     *              unsigned shorts in Java card, a negative number will be
     *              interpreted as positive value.
     */
    public void encodeUInt8(byte value) {
        encodeValue(TYPE_UNSIGNED_INTEGER, (short) (value & 0xFF));
    }

    /**
     * Encode the given integer value at the current buffer location.
     * 
     * @param value Value to encode in the byte array. Note: as there are no
     *              unsigned shorts in Java card, a negative number will be
     *              interpreted as positive value.
     */
    public void encodeUInt16(short value) {
        encodeValue(TYPE_UNSIGNED_INTEGER, value);
    }
    
    /**
     * Encodes the given byte array as 4 byte Integer
     */
    public void encodeUInt32(byte[] valueBuf, short valueOffset) {           
        writeRawByte((byte) (TYPE_UNSIGNED_INTEGER | ENCODED_FOUR_BYTES));            
        writeRawByteArray(valueBuf, valueOffset, (short) 4); 
    }

    /**
     * Encodes the given byte array as 8 byte Integer
     */
    public void encodeUInt64(byte[] valueBuf, short valueOffset) {           
        writeRawByte((byte) (TYPE_UNSIGNED_INTEGER | ENCODED_EIGHT_BYTES));            
        writeRawByteArray(valueBuf, valueOffset, (short) 8); 
    }
    
    private void encodeValue(byte majorType, short value) {      
        if(ICUtil.isLessThanAsUnsignedShort(value, ENCODED_ONE_BYTE)) {
            writeRawByte((byte) (majorType | value));  
        } else if (ICUtil.isLessThanAsUnsignedShort(value, (short) 0x100)) {
            writeUInt8(majorType, (byte) value);
        } else {
            writeUInt16(majorType, value);
        }        
    }
    
    
    private void writeUInt8(byte type, byte value) {   
        writeRawByte((byte) (type | ENCODED_ONE_BYTE));     
        writeRawByte(value);  
    }
    
    private void writeUInt16(byte type, short value) {           
        writeRawByte((byte) (type | ENCODED_TWO_BYTES));            
        writeRawShort(value); 
    }

    /**
     * Write the given byte at the current buffer location and increase the offset
     * by one.
     */
    final protected void writeRawByte(byte val) {
        mBuffer[mStatusWords[0]++] = val;
    }
    
    /**
     * Write the given short value at the current buffer location and increase the
     * offset by two.
     */
    final protected void writeRawShort(short val) {
        Util.setShort(mBuffer, mStatusWords[0], val);
        mStatusWords[0]+=2;
    }
    

    /**
     * Write the byte array at the current buffer location and increase the offset
     * by its size.
     */
    final protected short writeRawByteArray(byte[] value, short offset, short length) {
        if(length > (short) (value.length + offset)|| (short)(length + getCurrentOffset()) > getBufferLength())
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
        Util.arrayCopyNonAtomic(value, offset, mBuffer, getCurrentOffset(), length);
        
        increaseOffset(length);
        
        return length;
    }
}
