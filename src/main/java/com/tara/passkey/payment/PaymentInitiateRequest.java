package com.tara.passkey.payment;

public record PaymentInitiateRequest(String payeeVpa, String payeeName, long amountMinor, String currency, String purpose) {
}
