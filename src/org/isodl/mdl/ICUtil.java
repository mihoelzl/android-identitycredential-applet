package org.isodl.mdl;

public class ICUtil {

    public static short sign(short a) {
        return (byte) ((a >>> (short) 15) & 1);
    }

    public static short min(short a, short b) {
        if (sign(a) == sign(b))
            return (a < b ? a : b);
        else if (sign(a) == 1)
            return b;
        else
            return a;
    }

    public static void setBit(byte[] bitField, short flag, boolean value) {
        short byteIndex = (short) (flag >>> (short) 3);
        byte bitMask = (byte) ((byte) 1 << (short) (flag & (short) 0x0007));
        if (value) {
            bitField[byteIndex] ^= bitMask;
        } else {
            bitField[byteIndex] &= ~bitMask;
        }
    }

    public static boolean getBit(byte[] bitField, short flag) {
        short byteIndex = (short) (flag >>> (short) 3);
        byte bitMask = (byte) ((byte) 1 << (short) (flag & (short) 0x0007));
        return bitMask == (byte) (bitField[byteIndex] & bitMask);
    }
}
