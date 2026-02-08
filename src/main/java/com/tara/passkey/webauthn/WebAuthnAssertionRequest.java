package com.tara.passkey.webauthn;

public record WebAuthnAssertionRequest(String id, String rawId, String type, AssertionResponse response) {
    public record AssertionResponse(String clientDataJSON, String authenticatorData, String signature, String userHandle) {
    }
}
