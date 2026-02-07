package com.tara.passkey.payment;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PaymentIntentRepository extends JpaRepository<PaymentIntentEntity, Long> {
    Optional<PaymentIntentEntity> findByTxnId(String txnId);
}
