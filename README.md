# Android Identity Credential - JavaCard Applet

This is the corresponding JavaCard applet for [this reference implementation](https://github.com/mihoelzl/android-identitycredential-ese-hal) of the Android Identity Credential HAL.  It is intended to run on an embedded secure element and used to protect the confidentiality of identity credential keys and the integrity of data entries. 
Encryption and decryption of data entries as well as the creation of signatures is always performed by the applet. See the HAL documentation in AOSP for details how this encryption and signature creation is done. 

## Open issues 
* Signature over attestation certificate using keymaster attestation: in order to validate that the credential was indeed created within the secure element, the keymaster applet needs to sign the credential key (requires direct interaction with the keymaster applet). At the moment the credential attestation certificates are self-signed. 
* Verification of user authentication token: in order to authenticate the user, the authentication token received from the HAL needs to be verified (including a check that the timeout has not exceeded). This could be done by e.g. using an extension of the keymaster API.
* Begin and end date of validity period from trusted source: a potential solution is to use the time source in the authentication token. 
* Proper handling of certificate chains in reader authentication: a reader authentication request might consist of multiple certificate. Only the top certificate contains the public key of the current reader that is used to verify the reader authentication data. However, the public key of the parent certificate should be used to check the access control profile. This could be done in cooperation with the HAL implementation.
* In combination with the previous point: currently, only the public key is added to the provisioning signature. The current HAL requires the complete certicifate to be added to the signature.

## Open questions
* Should the applet store a checksum of the last previousAuditLogHash of each credential to protect against forking the "blockchain"?
* Swapping in and out the public ephemeral key allows an attacker to replay a session. Is that an issue?

## Further Todos
* Insert certificate validity period. 
* Implement persistent storage of direct access entries.
* Implement direct access entry retrieval.
