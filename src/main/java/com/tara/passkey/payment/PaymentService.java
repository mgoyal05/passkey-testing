package com.tara.passkey.payment;

import com.tara.passkey.model.UserEntity;
import com.tara.passkey.webauthn.Base64Url;
import com.tara.passkey.webauthn.WebAuthnAssertionRequest;
import com.tara.passkey.webauthn.WebAuthnService;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class PaymentService {
    private final PaymentIntentRepository intentRepository;
    private final PaymentChallengeRepository challengeRepository;
    private final WebAuthnService webAuthnService;
    private final SecureRandom secureRandom = new SecureRandom();

    public PaymentService(PaymentIntentRepository intentRepository,
                          PaymentChallengeRepository challengeRepository,
                          WebAuthnService webAuthnService) {
        this.intentRepository = intentRepository;
        this.challengeRepository = challengeRepository;
        this.webAuthnService = webAuthnService;
    }

    @Transactional
    public PaymentIntentEntity initiate(UserEntity user, PaymentInitiateRequest request) {
        PaymentIntentEntity intent = new PaymentIntentEntity();
        intent.setUser(user);
        intent.setTxnId(UUID.randomUUID().toString());
        intent.setPayeeVpa(request.payeeVpa());
        intent.setPayeeName(request.payeeName());
        intent.setAmountMinor(request.amountMinor());
        intent.setCurrency(request.currency());
        intent.setPurpose(request.purpose());
        intent.setNonce(UUID.randomUUID().toString());
        intent.setCreatedAt(Instant.now());
        intent.setStatus(PaymentStatus.INITIATED);
        return intentRepository.save(intent);
    }

    @Transactional
    public PaymentChallengeEntity createChallenge(PaymentIntentEntity intent) {
        if (intent.getStatus() != PaymentStatus.INITIATED) {
            throw new PaymentException("Invalid payment status");
        }
        String canonical = canonicalPayload(intent);
        String txnHashHex = hashHex(canonical);
        byte[] challenge = new byte[32];
        secureRandom.nextBytes(challenge);
        PaymentChallengeEntity challengeEntity = new PaymentChallengeEntity();
        challengeEntity.setIntent(intent);
        challengeEntity.setChallengeB64url(Base64Url.encode(challenge));
        challengeEntity.setTxnHashHex(txnHashHex);
        challengeEntity.setExpiresAt(Instant.now().plus(2, ChronoUnit.MINUTES));
        challengeEntity.setCreatedAt(Instant.now());
        challengeRepository.save(challengeEntity);
        intent.setStatus(PaymentStatus.CHALLENGE_ISSUED);
        intentRepository.save(intent);
        return challengeEntity;
    }

    @Transactional
    public void verifyAndAuthorize(PaymentIntentEntity intent, WebAuthnAssertionRequest request, String origin) {
        PaymentChallengeEntity challenge = challengeRepository.findTopByIntent_TxnIdOrderByCreatedAtDesc(intent.getTxnId())
                .orElseThrow(() -> new PaymentException("Challenge not found"));
        if (challenge.getUsedAt() != null || challenge.getExpiresAt().isBefore(Instant.now())) {
            throw new PaymentException("Challenge expired or used");
        }
        if (intent.getStatus() != PaymentStatus.CHALLENGE_ISSUED) {
            throw new PaymentException("Invalid payment status");
        }
        String canonical = canonicalPayload(intent);
        String txnHashHex = hashHex(canonical);
        if (!txnHashHex.equals(challenge.getTxnHashHex())) {
            throw new PaymentException("Transaction hash mismatch");
        }
        webAuthnService.verifyAssertionForUser(request, origin, Base64Url.decode(challenge.getChallengeB64url()), intent.getUser().getId());
        challenge.setUsedAt(Instant.now());
        intent.setStatus(PaymentStatus.AUTHORIZED);
        challengeRepository.save(challenge);
        intentRepository.save(intent);
    }

    @Transactional
    public PaymentExecutionResult execute(PaymentIntentEntity intent) {
        if (intent.getStatus() == PaymentStatus.EXECUTED) {
            return new PaymentExecutionResult(intent.getTxnId(), intent.getStatus(), "RRN-ALREADY");
        }
        if (intent.getStatus() != PaymentStatus.AUTHORIZED) {
            throw new PaymentException("Payment not authorized");
        }
        intent.setStatus(PaymentStatus.EXECUTED);
        intentRepository.save(intent);
        return new PaymentExecutionResult(intent.getTxnId(), intent.getStatus(), "RRN-" + intent.getTxnId().substring(0, 8));
    }

    public String canonicalPayload(PaymentIntentEntity intent) {
        return "txnId=" + intent.getTxnId() +
                "|payeeVpa=" + intent.getPayeeVpa() +
                "|payeeName=" + intent.getPayeeName() +
                "|amount=" + intent.getAmountMinor() +
                "|currency=" + intent.getCurrency() +
                "|purpose=" + intent.getPurpose() +
                "|ts=" + intent.getCreatedAt().toEpochMilli() +
                "|nonce=" + intent.getNonce();
    }

    private String hashHex(String canonical) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(canonical.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (Exception ex) {
            throw new PaymentException("Unable to hash", ex);
        }
    }
}
