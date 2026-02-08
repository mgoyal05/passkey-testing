package com.tara.passkey.payment;

public record PaymentExecutionResult(String txnId, PaymentStatus status, String rrn) {
}
