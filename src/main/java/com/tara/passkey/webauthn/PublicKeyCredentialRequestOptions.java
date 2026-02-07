package com.tara.passkey.webauthn;

import java.util.List;

public class PublicKeyCredentialRequestOptions {
    private String challenge;
    private String rpId;
    private long timeout;
    private String userVerification;
    private List<Object> allowCredentials = List.of();

    public static PublicKeyCredentialRequestOptions create(String challenge, String rpId, long timeout, String userVerification) {
        PublicKeyCredentialRequestOptions options = new PublicKeyCredentialRequestOptions();
        options.challenge = challenge;
        options.rpId = rpId;
        options.timeout = timeout;
        options.userVerification = userVerification;
        return options;
    }

    public String getChallenge() {
        return challenge;
    }

    public String getRpId() {
        return rpId;
    }

    public long getTimeout() {
        return timeout;
    }

    public String getUserVerification() {
        return userVerification;
    }

    public List<Object> getAllowCredentials() {
        return allowCredentials;
    }
}
