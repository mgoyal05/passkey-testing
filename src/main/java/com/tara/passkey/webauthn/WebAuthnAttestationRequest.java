package com.tara.passkey.webauthn;

import java.util.List;

public record WebAuthnAttestationRequest(String id, String rawId, String type, AttestationResponse response, List<String> transports) {
    public record AttestationResponse(String clientDataJSON, String attestationObject, String userHandle) {
    }
}
