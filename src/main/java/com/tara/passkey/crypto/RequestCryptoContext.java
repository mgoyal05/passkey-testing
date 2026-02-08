package com.tara.passkey.crypto;

import javax.crypto.SecretKey;

public class RequestCryptoContext {
    private final String requestId;
    private final String path;
    private final SecretKey aesKey;
    private final SecretKey macKey;

    public RequestCryptoContext(String requestId, String path, SecretKey aesKey, SecretKey macKey) {
        this.requestId = requestId;
        this.path = path;
        this.aesKey = aesKey;
        this.macKey = macKey;
    }

    public String getRequestId() {
        return requestId;
    }

    public String getPath() {
        return path;
    }

    public SecretKey getAesKey() {
        return aesKey;
    }

    public SecretKey getMacKey() {
        return macKey;
    }
}
