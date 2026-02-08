package com.tara.passkey.controller;

import com.tara.passkey.config.WebAuthnProperties;
import com.tara.passkey.model.UserEntity;
import com.tara.passkey.payment.PaymentChallengeEntity;
import com.tara.passkey.payment.PaymentExecutionResult;
import com.tara.passkey.payment.PaymentInitiateRequest;
import com.tara.passkey.payment.PaymentIntentEntity;
import com.tara.passkey.payment.PaymentIntentRepository;
import com.tara.passkey.payment.PaymentService;
import com.tara.passkey.security.SessionConstants;
import com.tara.passkey.service.UserService;
import com.tara.passkey.webauthn.PublicKeyCredentialRequestOptions;
import com.tara.passkey.webauthn.WebAuthnAssertionRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.util.Map;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PaymentController {
    private final PaymentService paymentService;
    private final PaymentIntentRepository intentRepository;
    private final UserService userService;
    private final WebAuthnProperties webAuthnProperties;

    public PaymentController(PaymentService paymentService,
                             PaymentIntentRepository intentRepository,
                             UserService userService,
                             WebAuthnProperties webAuthnProperties) {
        this.paymentService = paymentService;
        this.intentRepository = intentRepository;
        this.userService = userService;
        this.webAuthnProperties = webAuthnProperties;
    }

    @PostMapping("/api/payments/initiate")
    public Map<String, Object> initiate(@RequestBody PaymentInitiateRequest request, HttpSession session) {
        UserEntity user = loadUser(session);
        PaymentIntentEntity intent = paymentService.initiate(user, request);
        return Map.of("txnId", intent.getTxnId(), "status", intent.getStatus().name());
    }

    @PostMapping("/api/payments/{txnId}/details")
    public Map<String, Object> details(@PathVariable String txnId, HttpSession session) {
        UserEntity user = loadUser(session);
        PaymentIntentEntity intent = intentRepository.findByTxnId(txnId).orElseThrow();
        if (!intent.getUser().getId().equals(user.getId())) {
            throw new IllegalStateException("Unauthorized");
        }
        return Map.of(
                "txnId", intent.getTxnId(),
                "payeeVpa", intent.getPayeeVpa(),
                "payeeName", intent.getPayeeName(),
                "amountMinor", intent.getAmountMinor(),
                "currency", intent.getCurrency(),
                "purpose", intent.getPurpose(),
                "status", intent.getStatus().name()
        );
    }

    @PostMapping("/api/payments/{txnId}/webauthn/options")
    public PublicKeyCredentialRequestOptions options(@PathVariable String txnId, HttpSession session) {
        UserEntity user = loadUser(session);
        PaymentIntentEntity intent = intentRepository.findByTxnId(txnId).orElseThrow();
        if (!intent.getUser().getId().equals(user.getId())) {
            throw new IllegalStateException("Unauthorized");
        }
        PaymentChallengeEntity challenge = paymentService.createChallenge(intent);
        return PublicKeyCredentialRequestOptions.create(
                challenge.getChallengeB64url(),
                webAuthnProperties.getRpId(),
                120000,
                "required"
        );
    }

    @PostMapping("/api/payments/{txnId}/webauthn/finish")
    public Map<String, Object> finish(@PathVariable String txnId,
                                      @RequestBody WebAuthnAssertionRequest request,
                                      HttpServletRequest servletRequest,
                                      HttpSession session) {
        UserEntity user = loadUser(session);
        PaymentIntentEntity intent = intentRepository.findByTxnId(txnId).orElseThrow();
        if (!intent.getUser().getId().equals(user.getId())) {
            throw new IllegalStateException("Unauthorized");
        }
        paymentService.verifyAndAuthorize(intent, request, servletRequest.getHeader("Origin"));
        return Map.of("ok", true, "txnId", intent.getTxnId(), "status", intent.getStatus().name());
    }

    @PostMapping("/api/payments/{txnId}/execute")
    public PaymentExecutionResult execute(@PathVariable String txnId, HttpSession session) {
        UserEntity user = loadUser(session);
        PaymentIntentEntity intent = intentRepository.findByTxnId(txnId).orElseThrow();
        if (!intent.getUser().getId().equals(user.getId())) {
            throw new IllegalStateException("Unauthorized");
        }
        return paymentService.execute(intent);
    }

    private UserEntity loadUser(HttpSession session) {
        String mobileNumber = (String) session.getAttribute(SessionConstants.AUTHENTICATED_USER);
        if (mobileNumber == null) {
            throw new IllegalStateException("Not authenticated");
        }
        return userService.getOrCreateUser(mobileNumber, "Consumer");
    }
}
