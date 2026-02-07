package com.tara.passkey.payment;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PaymentChallengeRepository extends JpaRepository<PaymentChallengeEntity, Long> {
    Optional<PaymentChallengeEntity> findTopByIntent_TxnIdOrderByCreatedAtDesc(String txnId);
}
