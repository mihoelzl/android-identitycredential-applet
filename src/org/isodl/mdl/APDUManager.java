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

import javacard.framework.APDU;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class APDUManager {

    private static final short BUFFER_SIZE = 261;

    private static final short VALUE_OUTGOING_EXPECTED_LENGTH = 0;
    private static final short VALUE_OUTGOING_LENGTH = 1;
    private static final short VALUE_INCOMING_LENGTH = 2;
    private static final short VALUE_INCOMING_DATA_OFFSET = 3;
    private static final short STATUS_VALUES_SIZE = 4;

    private final byte[] mStatusFlags;
    private static final short FLAG_APDU_OUTGOING = 0;
    private static final short FLAG_APDU_RECEIVED = 1;
    private static final short STATUS_FLAGS_SIZE = 1;

    private byte[] mSendBuffer;
    private byte[] mReceiveBuffer;
    private short[] mStatusValues;

    public APDUManager() {
        mStatusValues = JCSystem.makeTransientShortArray(STATUS_VALUES_SIZE, JCSystem.CLEAR_ON_DESELECT);
        mStatusFlags = JCSystem.makeTransientByteArray(STATUS_FLAGS_SIZE, JCSystem.CLEAR_ON_DESELECT);
    }

    /**
     * Reset the internal state of this manager
     */
    public void reset() {
        mStatusValues[VALUE_OUTGOING_EXPECTED_LENGTH] = 0;
        mStatusValues[VALUE_OUTGOING_LENGTH] = 0;
        mStatusValues[VALUE_INCOMING_LENGTH] = 0;
        mStatusValues[VALUE_INCOMING_DATA_OFFSET] = 0;

        ICUtil.setBit(mStatusFlags, FLAG_APDU_OUTGOING, false);
        ICUtil.setBit(mStatusFlags, FLAG_APDU_RECEIVED, false);
    }

    /**
     * Process an APDU. Resets the state of the manager and copies the APDU buffer
     * into the internal memory.
     * 
     * @param apdu
     * @return Boolean indicating if this APDU should be processed (e.g. do not
     *         process when connection comes from contactless interface)
     */
    public boolean process(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        
        if (mSendBuffer == null) {
            mSendBuffer = JCSystem.makeTransientByteArray(BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
        }
        
        if (mReceiveBuffer == null) {
            mReceiveBuffer = JCSystem.makeTransientByteArray(BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
        }
        
        reset();
        
        Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CLA, mReceiveBuffer, ISO7816.OFFSET_CLA, (short)(ISO7816.OFFSET_EXT_CDATA - ISO7816.OFFSET_CLA));
        
        // TODO: check if there are other cases where selection is not allowed.
        // If there are, this method returns false

        if (isContactlessInterface()) {
            return false;
        }

        return true;
    }

    public boolean isContactlessInterface() {
        final byte protocol = (byte) (APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK);
        if (protocol == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A || protocol == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_B) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Returns the internal buffer for outgoing traffic
     */
    public byte[] getSendBuffer() {
        return mSendBuffer;
    }

    /**
     * Returns the internal buffer for incoming traffic
     */
    public byte[] getReceiveBuffer() {
        if(mReceiveBuffer == null)
            return APDU.getCurrentAPDUBuffer();
        return mReceiveBuffer;
    }

    /**
     * Offset in the incoming buffer for data
     */
    public short getOffsetIncomingData() {
        return mStatusValues[VALUE_INCOMING_DATA_OFFSET];
    }
    
    /**
     * Size of the incoming data
     */
    public short getReceivingLength() {
        return mStatusValues[VALUE_INCOMING_LENGTH];
    }

    /**
     * Size of the internal buffer for outgoing traffic 
     */
    public short getOutbufferLength() {
        return BUFFER_SIZE;
    }

    /**
     * Receives all incoming data and stores it in the internal buffer
     * 
     * @return Size of the incoming data
     * @throws ISOException
     */
    public short receiveAll() throws ISOException {
        if (ICUtil.getBit(mStatusFlags, FLAG_APDU_RECEIVED)) {
            return mStatusValues[VALUE_INCOMING_LENGTH];
        } else {
            final APDU apdu = APDU.getCurrentAPDU();
            
            short bytesReceived = apdu.setIncomingAndReceive();
            final short lc = apdu.getIncomingLength();
            final short receiveOffset = apdu.getOffsetCdata();
    
            byte[] receiveBuffer = getReceiveBuffer();
            final byte[] apduBuffer = apdu.getBuffer();

            if (bytesReceived != lc) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            
            Util.arrayCopyNonAtomic(apduBuffer, receiveOffset, receiveBuffer, apdu.getOffsetCdata(), bytesReceived);
            
            mStatusValues[VALUE_INCOMING_LENGTH] = lc;
            mStatusValues[VALUE_INCOMING_DATA_OFFSET] = apdu.getOffsetCdata();
            
            ICUtil.setBit(mStatusFlags, FLAG_APDU_RECEIVED, true);
            
            return lc;
        }
    }

    /**
     * Set the outgoing flag, indicating that data is returned to the sender
     * 
     * @return Expected length for the respond APDU
     */
    public short setOutgoing() {
        APDU apdu = APDU.getCurrentAPDU();
        mStatusValues[VALUE_OUTGOING_EXPECTED_LENGTH] = apdu.setOutgoing();
        ICUtil.setBit(mStatusFlags, FLAG_APDU_OUTGOING, true);

        return mStatusValues[VALUE_OUTGOING_EXPECTED_LENGTH];
    }

    /**
     * Set the length of the outgoing APDU
     */
    public void setOutgoingLength(short outLength) {
        mStatusValues[VALUE_OUTGOING_LENGTH] = outLength;
    }

    /**
     * Send all data from the internal outgoing buffer
     */
    public void sendAll() {
        APDU apdu = APDU.getCurrentAPDU();
        if (ICUtil.getBit(mStatusFlags, FLAG_APDU_OUTGOING)) {
            final short outLength = mStatusValues[VALUE_OUTGOING_LENGTH];
            apdu.setOutgoingLength(outLength);

            apdu.sendBytesLong(mSendBuffer, (short) 0, outLength);
        }
    }
}
