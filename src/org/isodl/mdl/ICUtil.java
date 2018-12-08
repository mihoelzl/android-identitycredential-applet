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

    /**
     * Compare two signed shorts as unsigned value. Returns true if n1 is truly
     * smaller, false otherwise.
     */
    public static boolean isLessThanAsUnsignedShort(short n1, short n2) {
        return (n1 < n2) ^ ((n1 < 0) != (n2 < 0));
    }
}
