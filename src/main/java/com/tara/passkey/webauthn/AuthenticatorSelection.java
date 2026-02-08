package com.tara.passkey.webauthn;

public record AuthenticatorSelection(String residentKey, String userVerification, String authenticatorAttachment) {
}
