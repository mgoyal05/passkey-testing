package com.tara.passkey;

import com.tara.passkey.model.UserEntity;
import com.tara.passkey.payment.PaymentIntentEntity;
import com.tara.passkey.payment.PaymentService;
import com.tara.passkey.payment.PaymentChallengeRepository;
import com.tara.passkey.payment.PaymentIntentRepository;
import com.tara.passkey.payment.PaymentException;
import com.tara.passkey.payment.PaymentStatus;
import com.tara.passkey.webauthn.WebAuthnService;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class PaymentServiceTest {

    @Test
    void canonicalPayloadIsStable() {
        PaymentService service = new PaymentService(Mockito.mock(PaymentIntentRepository.class),
                Mockito.mock(PaymentChallengeRepository.class),
                Mockito.mock(WebAuthnService.class));
        PaymentIntentEntity intent = new PaymentIntentEntity();
        intent.setTxnId("txn-1");
        intent.setPayeeVpa("payee@upi");
        intent.setPayeeName("Payee");
        intent.setAmountMinor(50025);
        intent.setCurrency("INR");
        intent.setPurpose("Invoice");
        intent.setNonce("nonce-1");
        intent.setCreatedAt(Instant.ofEpochMilli(123456789));

        String canonical = service.canonicalPayload(intent);
        assertThat(canonical).contains("txnId=txn-1").contains("amount=50025");
    }

    @Test
    void mismatchAmountFailsHashCheck() {
        PaymentService service = new PaymentService(Mockito.mock(PaymentIntentRepository.class),
                Mockito.mock(PaymentChallengeRepository.class),
                Mockito.mock(WebAuthnService.class));
        PaymentIntentEntity intent = new PaymentIntentEntity();
        intent.setTxnId("txn-1");
        intent.setPayeeVpa("payee@upi");
        intent.setPayeeName("Payee");
        intent.setAmountMinor(50025);
        intent.setCurrency("INR");
        intent.setPurpose("Invoice");
        intent.setNonce("nonce-1");
        intent.setCreatedAt(Instant.ofEpochMilli(123456789));

        String canonicalOriginal = service.canonicalPayload(intent);
        intent.setAmountMinor(60000);
        String canonicalModified = service.canonicalPayload(intent);
        assertThat(canonicalOriginal).isNotEqualTo(canonicalModified);
    }
}
