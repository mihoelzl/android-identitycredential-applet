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

public interface ISO7816 extends javacard.framework.ISO7816 {
    /**
     * Instructions for the Identity Credential Store
     */
    public static final byte INS_ICS_GET_VERSION = (byte) 0x50;
    public static final byte INS_ICS_CREATE_EPHEMERAL_KEY = (byte) 0x52;
    public static final byte INS_ICS_TEST_CBOR = (byte) 0x53;

    /**
     * Credential provisioning instructions
     */
    public static final byte INS_ICS_CREATE_CREDENTIAL = (byte) 0x10;
    public static final byte INS_ICS_GET_ATTESTATION_CERT = (byte) 0x11;
    public static final byte INS_ICS_PERSONALIZE_ACCESS_CONTROL = (byte) 0x12;
    public static final byte INS_ICS_PERSONALIZE_ATTRIBUTE = (byte) 0x13;
    public static final byte INS_ICS_SIGN_PERSONALIZED_DATA = (byte) 0x14;

    /**
     * Credential Management instructions
     */
    public static final byte INS_ICS_LOAD_CREDENTIAL_BLOB = (byte) 0x30;
    public static final byte INS_ICS_AUTHENTICATE = (byte) 0x31;
    public static final byte INS_ICS_LOAD_ACCESS_CONTROL_PROFILE = (byte) 0x32;
    public static final byte INS_ICS_GET_ENTRY = (byte) 0x3A;
    public static final byte INS_ICS_CREATE_SIGNATURE = (byte) 0x3B;
    public static final byte INS_ICS_CREATE_SIGNING_KEY= (byte) 0x40;
    
    /**
     * Instruction bytes for standard ISO7816-4 commands 
     */
    public static final byte INS_GET_RESPONSE = (byte) 0xC0;
}
