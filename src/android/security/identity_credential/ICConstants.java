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

public class ICConstants {
    public static final byte[] CBOR_MAPKEY_DOCTYPE = new byte[] { (byte) 0x64, (byte) 0x6F, (byte) 0x63, (byte) 0x54,
            (byte) 0x79, (byte) 0x70, (byte) 0x65 };

    public static final byte[] CBOR_MAPKEY_DOCTYPE_UC = new byte[] { (byte) 0x44, (byte) 0x6F, (byte) 0x63, (byte) 0x54,
            (byte) 0x79, (byte) 0x70, (byte) 0x65 };

    public static final byte[] CBOR_MAPKEY_ACCESSCONTROLPROFILES = new byte[] { (byte) 0x61, (byte) 0x63, (byte) 0x63,
            (byte) 0x65, (byte) 0x73, (byte) 0x73, (byte) 0x43, (byte) 0x6f, (byte) 0x6e, (byte) 0x74, (byte) 0x72,
            (byte) 0x6f, (byte) 0x6c, (byte) 0x50, (byte) 0x72, (byte) 0x6f, (byte) 0x66, (byte) 0x69, (byte) 0x6c,
            (byte) 0x65, (byte) 0x73 };

    public static final byte[] CBOR_MAPKEY_ENTRIES = new byte[] { (byte) 0x65, (byte) 0x6e, (byte) 0x74, (byte) 0x72,
            (byte) 0x69, (byte) 0x65, (byte) 0x73 };

    public static final byte[] CBOR_MAPKEY_NAMESPACES = new byte[] { (byte) 0x6E, (byte) 0x61, (byte) 0x6D, (byte) 0x65,
            (byte) 0x73, (byte) 0x70, (byte) 0x61, (byte) 0x63, (byte) 0x65, (byte) 0x73 };

    public static final byte[] CBOR_MAPKEY_TESTCREDENTIAL = new byte[] { (byte) 0x74, (byte) 0x65, (byte) 0x73,
            (byte) 0x74, (byte) 0x43, (byte) 0x72, (byte) 0x65, (byte) 0x64, (byte) 0x65, (byte) 0x6e, (byte) 0x74,
            (byte) 0x69, (byte) 0x61, (byte) 0x6c };

    public static final byte[] CBOR_MAPKEY_DIRECTLYAVAILABLE = new byte[] { 0x64, (byte) 0x69, (byte) 0x72, (byte) 0x65,
            (byte) 0x63, (byte) 0x74, (byte) 0x6c, (byte) 0x79, (byte) 0x41, (byte) 0x76, (byte) 0x61, (byte) 0x69,
            (byte) 0x6c, (byte) 0x61, (byte) 0x62, (byte) 0x6c, (byte) 0x65 };

    public static final byte[] CBOR_MAPKEY_VALUE = new byte[] { (byte) 0x76, (byte) 0x61, (byte) 0x6c, (byte) 0x75,
            (byte) 0x65 };

    public static final byte[] CBOR_MAPKEY_SESSIONTRANSCRIPT = new byte[] { (byte) 0x53, (byte) 0x65, (byte) 0x73,
            (byte) 0x73, (byte) 0x69, (byte) 0x6F, (byte) 0x6E, (byte) 0x54, (byte) 0x72, (byte) 0x61, (byte) 0x6E,
            (byte) 0x73, (byte) 0x63, (byte) 0x72, (byte) 0x69, (byte) 0x70, (byte) 0x74 };

    public static final byte[] CBOR_MAPKEY_RESPONSE = new byte[] { (byte) 0x52, (byte) 0x65, (byte) 0x73, (byte) 0x70,
            (byte) 0x6F, (byte) 0x6E, (byte) 0x73, (byte) 0x65 };

    public static final byte[] CBOR_MAPKEY_REQUEST = new byte[] { (byte) 0x52, (byte) 0x65, (byte) 0x71, (byte) 0x75,
            (byte) 0x65, (byte) 0x73, (byte) 0x74 };

    public static final byte[] CBOR_MAPKEY_READERAUTHPUBKEY = { (byte) 0x72, (byte) 0x65, (byte) 0x61, (byte) 0x64,
            (byte) 0x65, (byte) 0x72, (byte) 0x41, (byte) 0x75, (byte) 0x74, (byte) 0x68, (byte) 0x50, (byte) 0x75,
            (byte) 0x62, (byte) 0x4B, (byte) 0x65, (byte) 0x79 };

    public static final byte[] CBOR_MAPKEY_CAPABILITYTYPE = { (byte) 0x63, (byte) 0x61, (byte) 0x70, (byte) 0x61,
            (byte) 0x62, (byte) 0x69, (byte) 0x6C, (byte) 0x69, (byte) 0x74, (byte) 0x79, (byte) 0x54, (byte) 0x79,
            (byte) 0x70, (byte) 0x65 };

    public static final byte[] CBOR_MAPKEY_AUDITLOGENTRY = { (byte) 0x41, (byte) 0x75, (byte) 0x64, (byte) 0x69,
            (byte) 0x74, (byte) 0x4C, (byte) 0x6F, (byte) 0x67, (byte) 0x45, (byte) 0x6E, (byte) 0x74, (byte) 0x72,
            (byte) 0x79 };
}
