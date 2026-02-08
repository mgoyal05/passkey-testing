package com.tara.passkey;

import com.tara.passkey.webauthn.DeviceBoundPolicy;
import com.tara.passkey.webauthn.WebAuthnException;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class DeviceBoundPolicyTest {

    @Test
    void rejectsBackedUpCredential() {
        byte flags = AuthenticatorData.BIT_BS;
        AuthenticatorData data = new AuthenticatorData(new byte[32], flags, 0L);
        assertThatThrownBy(() -> DeviceBoundPolicy.enforce(data)).isInstanceOf(WebAuthnException.class);
    }

    @Test
    void allowsBackupEligibleCredential() {
        byte flags = AuthenticatorData.BIT_BE;
        AuthenticatorData data = new AuthenticatorData(new byte[32], flags, 0L);
        DeviceBoundPolicy.enforce(data);
    }
}
