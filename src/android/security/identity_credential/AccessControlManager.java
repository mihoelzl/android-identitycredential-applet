package android.security.identity_credential;

import javacard.framework.JCSystem;

public class AccessControlManager {

    private static final byte STATUS_BEGIN = 0;
    private static final byte STATUS_AUTHENTICATION = 1;
    private static final byte STATUS_LOADPROFILES = 2;
    private static final byte STATUS_GETENTRIES = 3;
    
    private static final byte VALUE_CURRENT_STATUS = 0;
    private static final byte STATUS_WORDS = 1;
    
    private final byte[] mStatusWords;

    public AccessControlManager() {
        mStatusWords = JCSystem.makeTransientByteArray(STATUS_WORDS, JCSystem.CLEAR_ON_DESELECT);
    }
    
    
}
