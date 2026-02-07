package com.tara.passkey.webauthn;

import java.time.Instant;

public record WebAuthnChallenge(byte[] challenge, byte[] userHandle, String mobileNumber, Instant expiresAt) {
}
