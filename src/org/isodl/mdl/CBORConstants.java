package org.isodl.mdl;

public class CBORConstants {
    
    static final byte MAJOR_TYPE_MASK = (byte) 0xE0;
    
    // Major type 0: an unsigned integer
    static final byte TYPE_UNSIGNED_INTEGER = (byte) (0x00 << 5);
    // Major type 1: a negative integer
    static final byte TYPE_NEGATIVE_INTEGER = (byte) (0x01 << 5);
    // Major type 2: a byte string
    static final byte TYPE_BYTE_STRING = (byte) (0x02 << 5);
    // Major type 3: a text string
    static final byte TYPE_TEXT_STRING = (byte) (0x03 << 5);
    // Major type 4: an array of data items
    static final byte TYPE_ARRAY = (byte) (0x04 << 5);
    // Major type 5: a map of pairs of data items
    static final byte TYPE_MAP = (byte) (0x05 << 5);
    // Major type 6: optional semantic tagging of other major types
    static final byte TYPE_TAG = (byte) (0x06 << 5);
    // Major type 7: floating-point numbers
    static final byte TYPE_FLOAT = (byte) (0x07 << 5);

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

}
