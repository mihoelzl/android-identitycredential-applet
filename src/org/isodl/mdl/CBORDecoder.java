package org.isodl.mdl;

import javacardx.framework.util.intx.JCint;

public class CBORDecoder {

    static final byte EVENT_ERROR = (byte) 0x00;
    static final byte EVENT_EOF = (byte) 0xFF;

    static final byte EVENT_NEED_MORE_INPUT = (byte) 0x01;

    static final byte EVENT_VALUE_INT8 = (byte) 0x10;
    static final byte EVENT_VALUE_INT16 = (byte) 0x11;
    static final byte EVENT_VALUE_INT32 = (byte) 0x12;
    static final byte EVENT_VALUE_INT64 = (byte) 0x13;
    // public final byte EVENT_VALUE_NEGATIVE_INTEGER = (byte) 0x13;
    
    static final byte EVENT_VALUE_BYTESTRING = (byte) 0x20;
    static final byte EVENT_VALUE_ARRAY_BEGIN = (byte) 0x30;
    static final byte EVENT_VALUE_ARRAY_END = (byte) 0x31;
    static final byte EVENT_VALUE_MAP = (byte) 0x40;

    private byte mCurrentEvent;
    
    private byte[] mCurrentBuffer;
    
    public CBORDecoder(){
        
    }
    /**
     * Feed input data to the decoder. The decoder will copy the data in a separate
     * buffer and interpret the next event. If the next event cannot be fully
     * interpreted, more data needs to be fed to the decoder.
     * 
     * @param cborInput
     * @param offset
     * @param length
     * @return Number of bytes read from the input and interpreted.
     */
    public short feed(byte[] cborInput, short offset, short length) {
        if(length==0) {
            mCurrentEvent = EVENT_NEED_MORE_INPUT;
            return mCurrentEvent;
        }
        mCurrentBuffer = cborInput;
        return 0;
    }

    public short finish() {

        return 0;
    }

    /**
     * Returns the next event
     * 
     * @return
     */
    public byte nextEvent() {
        int t = JCint.getInt(mCurrentBuffer, (short)0);
        
        byte length = (byte) (mCurrentBuffer[0] & CBORConstants.ADDINFO_MASK);
        byte value;
        
        if(length < CBORConstants.ONE_BYTE) {
            value = length;
        }
        
        switch(mCurrentBuffer[0] & CBORConstants.MAJOR_TYPE_MASK) {
        case CBORConstants.TYPE_UNSIGNED_INTEGER:
        case CBORConstants.TYPE_NEGATIVE_INTEGER:
            mCurrentEvent = EVENT_VALUE_INT16;
            break;
        case CBORConstants.TYPE_ARRAY:
            break;
        case CBORConstants.TYPE_MAP:
            break;
        }
        
        return EVENT_EOF;
    }

    public short getCurrentInteger() {

        return 0;
    }

    public short getCurrentShort() {

        return 0;
    }

    public short getCurrentArrayLength() {

        return 0;
    }

    public short getCurrentMapLength() {

        return 0;
    }
    public short getCurrentMapKey(byte[] outByteString, short offset) {

        return 0;
    }
    
    public short getCurrentByteString(byte[] outByteString, short offset) {

        return 0;
    }

}
