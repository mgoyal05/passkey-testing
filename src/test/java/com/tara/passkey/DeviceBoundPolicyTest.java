package com.tara.passkey;

import com.tara.passkey.webauthn.DeviceBoundPolicy;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import org.junit.jupiter.api.Test;

public class DeviceBoundPolicyTest {

    @Test
    void allowsBackupEligibleCredential() {
        byte flags = AuthenticatorData.BIT_BE;
        AuthenticatorData data = new AuthenticatorData(new byte[32], flags, 0L);
        DeviceBoundPolicy.enforce(data);
    }

    @Test
    void allowsBackedUpCredential() {
        byte flags = AuthenticatorData.BIT_BS;
        AuthenticatorData data = new AuthenticatorData(new byte[32], flags, 0L);
        DeviceBoundPolicy.enforce(data);
    }
}
