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

package android.security.identity_credential;

import javacard.framework.APDU;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class APDUManager {

    // Buffer size for processing outgoing traffic
    private static final short BUFFER_SIZE = 261;
    
    // Buffer size for large incoming/outgoing traffic. 
    // TODO: change it to larger size for, e.g. pictures (0x1000)
    public static final short MAXCHUNKSIZE = 0x200; 

    private static final byte VALUE_OUTGOING_EXPECTED_LENGTH = 0;
    private static final byte VALUE_OUTGOING_LENGTH = 1;
    private static final byte VALUE_OUTGOING_DATA_SENT = 2;
    private static final byte VALUE_INCOMING_LENGTH = 3;
    private static final byte VALUE_INCOMING_DATA_OFFSET = 4;
    private static final byte STATUS_VALUES_SIZE = 5;

    private static final byte FLAG_APDU_OUTGOING = 0;
    private static final byte FLAG_APDU_OUTGOING_MOREDATA = 1;
    private static final byte FLAG_APDU_OUTGOING_LARGEBUFFER = 2;
    private static final byte FLAG_APDU_RECEIVED = 3;
    private static final byte FLAG_APDU_RECEIVE_MOREDATA = 4;
    private static final byte FLAG_APDU_RECEIVED_LARGEBUFFER = 5;
    private static final byte STATUS_FLAGS_SIZE = 1;

    private final byte[] mStatusFlags;
    private final short[] mStatusValues;
    private final byte[] mLargeSendAndRecvBuffer;
    private byte[] mSendBuffer;

    public APDUManager() {
        mStatusValues = JCSystem.makeTransientShortArray(STATUS_VALUES_SIZE, JCSystem.CLEAR_ON_DESELECT);
        mStatusFlags = JCSystem.makeTransientByteArray(STATUS_FLAGS_SIZE, JCSystem.CLEAR_ON_DESELECT);
        
        mLargeSendAndRecvBuffer = JCSystem.makeTransientByteArray(MAXCHUNKSIZE, JCSystem.CLEAR_ON_DESELECT);
    }

    /**
     * Reset the internal state of this manager
     */
    public void reset() {
        mStatusValues[VALUE_OUTGOING_EXPECTED_LENGTH] = 0;
        mStatusValues[VALUE_OUTGOING_LENGTH] = 0;
        mStatusValues[VALUE_INCOMING_LENGTH] = 0;
        mStatusValues[VALUE_INCOMING_DATA_OFFSET] = 0;
        mStatusValues[VALUE_OUTGOING_DATA_SENT] = 0;
    }

    /**
     * Process an APDU. Resets the state of the manager and copies the APDU buffer
     * into the internal memory.
     * 
     * @param apdu 
     * @return Boolean indicating if this APDU should be further processed (e.g. has
     *         already been processed by APDU manager for large incoming/outgoing
     *         traffic or disallow processing for contactless interface)
     */
    public boolean process(APDU apdu) {
        byte[] buf = apdu.getBuffer();

        // TODO: check if there are other cases where selection is not allowed.
        // If there are, this method returns false
        if (isContactlessInterface()) {
            return false;
        }

        ICUtil.setBit(mStatusFlags, FLAG_APDU_OUTGOING, false);
        ICUtil.setBit(mStatusFlags, FLAG_APDU_RECEIVED, false);
        
        if(buf[ISO7816.OFFSET_INS] == ISO7816.INS_GET_RESPONSE) {
            if(!ICUtil.getBit(mStatusFlags, FLAG_APDU_OUTGOING_MOREDATA)) {
                return false;
            }
            apdu.setIncomingAndReceive();
            
            short lenToSend = apdu.setOutgoing();
            
            if (((short) (mStatusValues[VALUE_OUTGOING_DATA_SENT] + lenToSend)) >= mStatusValues[VALUE_OUTGOING_LENGTH]) {
                // Sent enough, finish up
                lenToSend = (short) (mStatusValues[VALUE_OUTGOING_LENGTH] - mStatusValues[VALUE_OUTGOING_DATA_SENT]);
                ICUtil.setBit(mStatusFlags, FLAG_APDU_OUTGOING_MOREDATA, false);
            }
            apdu.setOutgoingLength(lenToSend);
            apdu.sendBytesLong(getSendBuffer(), mStatusValues[VALUE_OUTGOING_DATA_SENT], lenToSend);

            mStatusValues[VALUE_OUTGOING_DATA_SENT] += lenToSend;
            if(ICUtil.getBit(mStatusFlags, FLAG_APDU_OUTGOING_MOREDATA)) {
                ISOException.throwIt(ISO7816.SW_BYTES_REMAINING_00);
            }
            return false;
        }
        
        // More APDUs coming, store the full data (e.g. picture) in flash 
        if (apdu.isCommandChainingCLA()) {
            if (!ICUtil.getBit(mStatusFlags, FLAG_APDU_RECEIVE_MOREDATA)) {
                // First command
                Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CLA, mLargeSendAndRecvBuffer, ISO7816.OFFSET_CLA, (short)(ISO7816.OFFSET_EXT_CDATA - ISO7816.OFFSET_CLA));    

                ICUtil.setBit(mStatusFlags, FLAG_APDU_RECEIVE_MOREDATA, true);
                
                mStatusValues[VALUE_INCOMING_LENGTH] = 0;
            }
            receiveAll();
            
            // No processing until all data is received (incremental processing not support)
            return false;  
        } else if(ICUtil.getBit(mStatusFlags, FLAG_APDU_RECEIVE_MOREDATA)) {
            // Last command in chain
            receiveAll();
            ICUtil.setBit(mStatusFlags, FLAG_APDU_RECEIVE_MOREDATA, false);
            ICUtil.setBit(mStatusFlags, FLAG_APDU_RECEIVED_LARGEBUFFER, true);
        } else {
            // No data has been processed, reset the internal state
            reset();
            
            ICUtil.setBit(mStatusFlags, FLAG_APDU_OUTGOING_LARGEBUFFER, false);
            ICUtil.setBit(mStatusFlags, FLAG_APDU_RECEIVED_LARGEBUFFER, false);
        }
        
        if (mSendBuffer == null) {
            short bufferSize = ICUtil.max(BUFFER_SIZE, (short)buf.length); // extended length APDUs?
            mSendBuffer = JCSystem.makeTransientByteArray(bufferSize, JCSystem.CLEAR_ON_DESELECT);
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
     * Returns the internal buffer for outgoing traffic. This method will return the
     * common large buffer when support was enabled in setOutgoing
     */
    public byte[] getSendBuffer() {
        if(ICUtil.getBit(mStatusFlags, FLAG_APDU_OUTGOING_LARGEBUFFER)) {
            return mLargeSendAndRecvBuffer;
        }
        return mSendBuffer;
    }
    
    /**
     * Returns the internal buffer for incoming traffic
     */
    public byte[] getReceiveBuffer() {
        if (ICUtil.getBit(mStatusFlags, FLAG_APDU_RECEIVED_LARGEBUFFER)) {
            return mLargeSendAndRecvBuffer;            
        }
        return APDU.getCurrentAPDUBuffer();
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
        if(ICUtil.getBit(mStatusFlags, FLAG_APDU_OUTGOING_LARGEBUFFER)) {
            return MAXCHUNKSIZE;
        }
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
    
            final byte[] apduBuffer = apdu.getBuffer();

            if (bytesReceived != lc) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            
            if (ICUtil.getBit(mStatusFlags, FLAG_APDU_RECEIVE_MOREDATA)) {
                // Large data, copy into large receiving buffer
                
                // New offset = general data offset + already received data
                short newDataOffset = (short) (receiveOffset + getReceivingLength()); 
                if ((short) (newDataOffset + bytesReceived) > MAXCHUNKSIZE) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                }
                
                Util.arrayCopyNonAtomic(apduBuffer, receiveOffset, mLargeSendAndRecvBuffer, newDataOffset, bytesReceived);
                mStatusValues[VALUE_INCOMING_LENGTH] += lc;
            } else {
                mStatusValues[VALUE_INCOMING_LENGTH] = lc;
            }
            
            mStatusValues[VALUE_INCOMING_DATA_OFFSET] = receiveOffset;                
            
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
        return setOutgoing(false);
    }

    /**
     * Set the outgoing flag, indicating that data is returned to the sender
     * 
     * @param largeBuffer Use the large EEPROM buffer for outgoing traffic. Note:
     *                    the caller needs to support a "one buffer" implementation
     *                    for receiving and outgoing data. This method will then
     *                    return the common large buffer.
     * @return Expected length for the respond APDU
     */
    public short setOutgoing(boolean largeBuffer) {
        APDU apdu = APDU.getCurrentAPDU();
        mStatusValues[VALUE_OUTGOING_EXPECTED_LENGTH] = apdu.setOutgoing();
        ICUtil.setBit(mStatusFlags, FLAG_APDU_OUTGOING, true);
        ICUtil.setBit(mStatusFlags, FLAG_APDU_OUTGOING_LARGEBUFFER, largeBuffer);

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
        final APDU apdu = APDU.getCurrentAPDU();
        if (ICUtil.getBit(mStatusFlags, FLAG_APDU_OUTGOING)) {
            short outLength = mStatusValues[VALUE_OUTGOING_LENGTH];
            if(outLength > mStatusValues[VALUE_OUTGOING_EXPECTED_LENGTH]) {
                
                outLength = mStatusValues[VALUE_OUTGOING_EXPECTED_LENGTH];
                
                ICUtil.setBit(mStatusFlags, FLAG_APDU_OUTGOING_MOREDATA, true);
                
                mStatusValues[VALUE_OUTGOING_DATA_SENT] = outLength;
            } 
            apdu.setOutgoingLength(outLength);                
            
            apdu.sendBytesLong(getSendBuffer(), (short) 0, outLength);
            
            if(ICUtil.getBit(mStatusFlags, FLAG_APDU_OUTGOING_MOREDATA)) {
                ISOException.throwIt(ISO7816.SW_BYTES_REMAINING_00);
            }
        }
    }
}
