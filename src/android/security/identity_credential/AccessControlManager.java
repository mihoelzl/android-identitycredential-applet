package android.security.identity_credential;

import javacard.framework.JCSystem;
import javacard.framework.Util;

public class AccessControlManager {

    private static final byte STATUS_AUTHENTICATION = 0;
    private static final byte STATUS_LOADPROFILES = 1;
    private static final byte STATUS_GETENTRIES = 2;
    
    private static final byte VALUE_CURRENT_STATUS = 0;
    private static final byte STATUS_WORDS = 1;

    private static final short TEMPBUFFER_SIZE = 128;
    private static final short BUFFERPOS_READERKEY = 0;
    private static final short BUFFERPOS_USERID = BUFFERPOS_READERKEY + 65;
    private static final short BUFFERPOS_PROFILEIDS = BUFFERPOS_USERID + 32;
    
    private final byte[] mStatusWords;
    
    private final byte[] mTempBuffer;

    private final CryptoManager mCryptoManager;
    
    public AccessControlManager(CryptoManager cryptoManager) {
        mCryptoManager = cryptoManager;

        mTempBuffer  = JCSystem.makeTransientByteArray(TEMPBUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
             
        mStatusWords = JCSystem.makeTransientByteArray(STATUS_WORDS, JCSystem.CLEAR_ON_DESELECT);
    }
    
    public void reset() {
        setStatus(STATUS_AUTHENTICATION);
    }
    
    public void authenticationDone() {
        setStatus(STATUS_LOADPROFILES);
    }
    
    public void profilesLoaded() {
        setStatus(STATUS_GETENTRIES);
    }
    
    
    public void setStatus(byte status) {
        mStatusWords[VALUE_CURRENT_STATUS] = status;
    }
    
    public boolean authenticateReader(byte[] sessionTranscript, short offset, short length, byte[] rederSignature,
            short readerSignatureOffset, short readerSignatureLength) {
        
        // TODO parse reader public key and ephemeral key from session transcript
        // TODO verify the signature over transcript
        // mCryptoManager.verifyReaderSignature()
        
        // TODO verify that the ephemeral key has not changed
        // mCryptoManager.verifyEphemeralKey(holderPubKey, holderKeyOffset, holderKeyLength);
        
        return true;
    }
    
    public boolean authenticateUser(byte[] authToken, short tokenOffset, short tokenLen) {
        // TODO: How to we verify the token?
        
        Util.arrayCopyNonAtomic(authToken, tokenOffset, mTempBuffer, BUFFERPOS_USERID, tokenLen);
        
        return true;
    }
}
