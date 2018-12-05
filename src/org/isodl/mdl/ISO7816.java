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

public interface ISO7816 extends javacard.framework.ISO7816 {
    /**
     * Standard ISO7816 instructions
     */
    public static final byte INS_READ_BINARY = (byte) 0xB0;
    public static final byte INS_READ_BINARY_EXT = (byte) 0xB1;

    public static final byte INS_GET_DATA = (byte) 0xCA;
    public static final byte INS_GET_DATA_EXT = (byte) 0xCB;

    /**
     * Instructions for the Identity Credential Store
     */
    public static final byte INS_ICS_GET_VERSION = (byte) 0x50;
    public static final byte INS_ICS_PING = (byte) 0x51;
    public static final byte INS_ICS_TEST_CBOR = (byte) 0x91;

    /**
     * Credential provisioning instructions
     */
    public static final byte INS_ICS_CREATE_CREDENTIAL = (short) 0x10;
    public static final byte INS_ICS_GET_ATTESTATION_CERT = (short) 0x11;
    public static final byte INS_ICS_PERSONALIZE_CREDENTIAL = (short) 0x12;
    public static final byte INS_ICS_ENCRYPT_ENTRIES = (short) 0x41;

    /**
     * Credential Management instructions
     */
    public static final byte INS_ICS_LOAD_CREDENTIAL_BLOB = (short) 0x30;
    public static final byte INS_ICS_AUTHENTICATE = (short) 0x31;
    public static final byte INS_ICS_LOAD_ACCESS_CONTROL_PROFILE = (short) 0x32;
    public static final byte INS_ICS_GET_ENTRY = (short) 0x3A;
    public static final byte INS_ICS_CREATE_SIGNATURE = (short) 0x3B;
    public static final byte INS_ICS_GENERATE_NEW_SIGNING_KEY= (short) 0x40;
    
    /**
     * Status words
     */
    public static final short SW_OK = (short) 0x9000;
    public static final short SW_REFERENCE_DATA_NOT_FOUND = (short) 0x6A88;
    public static final short SW_INTERNAL_ERROR = (short) 0x6d66;
    public static final short SW_SM_DO_MISSING = (short) 0x6987;
    public static final short SW_SM_DO_INCORRECT = (short) 0x6988;
    public static final short SW_NOT_ENOUGH_MEMORY = (short) 0x6A84;
}
