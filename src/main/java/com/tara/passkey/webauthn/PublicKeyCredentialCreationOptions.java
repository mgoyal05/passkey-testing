package com.tara.passkey.webauthn;

import java.util.List;

public class PublicKeyCredentialCreationOptions {
    private String challenge;
    private RpEntity rp;
    private UserEntityInfo user;
    private List<PubKeyCredParam> pubKeyCredParams;
    private AuthenticatorSelection authenticatorSelection;
    private long timeout;
    private String attestation;

    public static PublicKeyCredentialCreationOptions create(String challenge, RpEntity rp, UserEntityInfo user,
                                                            List<PubKeyCredParam> params, AuthenticatorSelection selection,
                                                            long timeout, String attestation) {
        PublicKeyCredentialCreationOptions options = new PublicKeyCredentialCreationOptions();
        options.challenge = challenge;
        options.rp = rp;
        options.user = user;
        options.pubKeyCredParams = params;
        options.authenticatorSelection = selection;
        options.timeout = timeout;
        options.attestation = attestation;
        return options;
    }

    public String getChallenge() {
        return challenge;
    }

    public RpEntity getRp() {
        return rp;
    }

    public UserEntityInfo getUser() {
        return user;
    }

    public List<PubKeyCredParam> getPubKeyCredParams() {
        return pubKeyCredParams;
    }

    public AuthenticatorSelection getAuthenticatorSelection() {
        return authenticatorSelection;
    }

    public long getTimeout() {
        return timeout;
    }

    public String getAttestation() {
        return attestation;
    }
}
