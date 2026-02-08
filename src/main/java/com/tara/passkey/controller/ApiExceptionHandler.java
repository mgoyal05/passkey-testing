package com.tara.passkey.controller;

import com.tara.passkey.crypto.CryptoValidationException;
import com.tara.passkey.payment.PaymentException;
import com.tara.passkey.webauthn.WebAuthnException;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(WebAuthnException.class)
    public ResponseEntity<Map<String, Object>> handleWebAuthn(WebAuthnException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", ex.getMessage()));
    }

    @ExceptionHandler(PaymentException.class)
    public ResponseEntity<Map<String, Object>> handlePayment(PaymentException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", ex.getMessage()));
    }

    @ExceptionHandler(CryptoValidationException.class)
    public ResponseEntity<Map<String, Object>> handleCrypto(CryptoValidationException ex) {
        return ResponseEntity.status(ex.getStatus()).body(Map.of("error", ex.getMessage()));
    }
}
