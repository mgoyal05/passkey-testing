package com.tara.passkey.crypto;

import org.springframework.http.HttpStatus;

public class CryptoValidationException extends RuntimeException {
    private final HttpStatus status;

    public CryptoValidationException(String message, HttpStatus status) {
        super(message);
        this.status = status;
    }

    public CryptoValidationException(String message, HttpStatus status, Throwable cause) {
        super(message, cause);
        this.status = status;
    }

    public HttpStatus getStatus() {
        return status;
    }
}
