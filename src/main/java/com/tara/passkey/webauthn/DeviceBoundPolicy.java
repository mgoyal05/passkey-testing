package com.tara.passkey.webauthn;

import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;

public final class DeviceBoundPolicy {
    private DeviceBoundPolicy() {
    }

    public static void enforce(AuthenticatorData authenticatorData) {
        if (authenticatorData.isFlagBS()) {
            throw new WebAuthnException("Backed up credentials are not allowed");
        }
    }
}
