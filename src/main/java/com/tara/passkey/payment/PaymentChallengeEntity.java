package com.tara.passkey.payment;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.Instant;

@Entity
@Table(name = "payment_challenges")
public class PaymentChallengeEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "intent_id", nullable = false)
    private PaymentIntentEntity intent;

    @Column(name = "challenge_b64url", nullable = false)
    private String challengeB64url;

    @Column(name = "txn_hash_hex", nullable = false)
    private String txnHashHex;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "used_at")
    private Instant usedAt;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public PaymentIntentEntity getIntent() {
        return intent;
    }

    public void setIntent(PaymentIntentEntity intent) {
        this.intent = intent;
    }

    public String getChallengeB64url() {
        return challengeB64url;
    }

    public void setChallengeB64url(String challengeB64url) {
        this.challengeB64url = challengeB64url;
    }

    public String getTxnHashHex() {
        return txnHashHex;
    }

    public void setTxnHashHex(String txnHashHex) {
        this.txnHashHex = txnHashHex;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }

    public Instant getUsedAt() {
        return usedAt;
    }

    public void setUsedAt(Instant usedAt) {
        this.usedAt = usedAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }
}
