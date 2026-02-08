package com.tara.passkey.webauthn;

public class WebAuthnException extends RuntimeException {
    public WebAuthnException(String message) {
        super(message);
    }

    public WebAuthnException(String message, Throwable cause) {
        super(message, cause);
    }
}
