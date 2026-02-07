package com.tara.passkey.webauthn;

import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;

public final class DeviceBoundPolicy {
    private DeviceBoundPolicy() {
    }

    public static void enforce(AuthenticatorData authenticatorData) {
        if (authenticatorData.isFlagBE() || authenticatorData.isFlagBS()) {
            throw new WebAuthnException("Backup eligible or backed up credentials are not allowed");
        }
    }
}
