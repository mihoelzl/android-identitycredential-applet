# Android Identity Credential HAL Implementation - JavaCard Applet

This is the corresponding JavaCard applet for [this reference implementation](https://github.com/mihoelzl/android-identitycredential-ese-hal) of the Android Identity Credential HAL.  It is intended to run on an embedded secure element and used to protect the confidentiality of identity credential keys and the integrity of data entries. 
Encryption and decryption of data entries as well as the creation of signatures is always performed by the applet. See the HAL documentation in AOSP for details how this encryption and signature creation is done. 

Open issues and todos of this applet implementation:
* Signature over attestation certificate using keymaster attestation: in order to validate that the credential was indeed created within the secure element, the keymaster applet needs to sign the credential key (requires direct interaction with the keymaster applet). At the moment the credential attestation certificates are self-signed. 
* Verification of user authentication token. 
* Proper handling of certificate chains in reader authentication.
* Insert certificate validity period. 
* Implement direct access.
 
