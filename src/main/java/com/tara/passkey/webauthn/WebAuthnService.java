package com.tara.passkey.webauthn;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tara.passkey.config.WebAuthnProperties;
import com.tara.passkey.model.UserEntity;
import com.tara.passkey.model.WebAuthnCredentialEntity;
import com.tara.passkey.repository.WebAuthnCredentialRepository;
import com.tara.passkey.service.UserService;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.AuthenticatorTransport;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;

@Service
public class WebAuthnService {
    private final WebAuthnProperties properties;
    private final WebAuthnCredentialRepository credentialRepository;
    private final UserService userService;
    private final WebAuthnChallengeStore challengeStore;
    private final ObjectMapper objectMapper;
    private final SecureRandom secureRandom = new SecureRandom();
    private final ObjectConverter objectConverter = new ObjectConverter();
    private final AttestationObjectConverter attestationConverter = new AttestationObjectConverter(objectConverter);
    private final AuthenticatorDataConverter authenticatorDataConverter = new AuthenticatorDataConverter(objectConverter);

    public WebAuthnService(WebAuthnProperties properties,
                           WebAuthnCredentialRepository credentialRepository,
                           UserService userService,
                           WebAuthnChallengeStore challengeStore,
                           ObjectMapper objectMapper) {
        this.properties = properties;
        this.credentialRepository = credentialRepository;
        this.userService = userService;
        this.challengeStore = challengeStore;
        this.objectMapper = objectMapper;
    }

    public PublicKeyCredentialCreationOptions startRegistration(String sessionId, String mobileNumber, String customerType) {
        byte[] challenge = randomChallenge();
        byte[] userHandle = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
        challengeStore.saveRegistration(sessionId, new WebAuthnChallenge(challenge, userHandle, mobileNumber, Instant.now().plus(5, ChronoUnit.MINUTES)));
        return PublicKeyCredentialCreationOptions.create(
                Base64Url.encode(challenge),
                new RpEntity(properties.getRpId(), properties.getRpName()),
                new UserEntityInfo(Base64Url.encode(userHandle), mobileNumber, mobileNumber),
                List.of(
                        new PubKeyCredParam("public-key", -7),
                        new PubKeyCredParam("public-key", -257)
                ),
                new AuthenticatorSelection("required", "required", "platform"),
                60000,
                "none"
        );
    }

    public void finishRegistration(String sessionId, WebAuthnAttestationRequest request, String origin) {
        WebAuthnChallenge challenge = challengeStore.consumeRegistration(sessionId);
        if (challenge == null) {
            throw new WebAuthnException("Missing challenge");
        }
        byte[] clientData = Base64Url.decode(request.response().clientDataJSON());
        byte[] attestationObject = Base64Url.decode(request.response().attestationObject());
        validateClientData(clientData, challenge.challenge(), origin, "webauthn.create");

        AttestationObject attestation = attestationConverter.convert(attestationObject);
        AuthenticatorData authenticatorData = attestation.getAuthenticatorData();
        verifyRpIdHash(authenticatorData.getRpIdHash());
        if (!authenticatorData.isFlagUV()) {
            throw new WebAuthnException("User verification required");
        }
        DeviceBoundPolicy.enforce(authenticatorData);

        UserEntity user = userService.getOrCreateUser(challenge.mobileNumber(), "Consumer");
        WebAuthnCredentialEntity credential = new WebAuthnCredentialEntity();
        credential.setUser(user);
        credential.setCredentialId(Base64Url.encode(authenticatorData.getAttestedCredentialData().getCredentialId()));
        byte[] coseKeyBytes = objectConverter.getCborConverter().writeValueAsBytes(authenticatorData.getAttestedCredentialData().getCOSEKey());
        credential.setPublicKey(Base64Url.encode(coseKeyBytes));
        credential.setSignCount(authenticatorData.getSignCount());
        credential.setBackupEligible(authenticatorData.isFlagBE());
        credential.setBackupState(authenticatorData.isFlagBS());
        credential.setTransports(String.join(",", request.transports() != null ? request.transports() : List.of()));
        credential.setCreatedAt(Instant.now());
        credential.setLastUsedAt(Instant.now());
        credentialRepository.save(credential);
    }

    public PublicKeyCredentialRequestOptions startAuthentication(String sessionId) {
        byte[] challenge = randomChallenge();
        challengeStore.saveAuthentication(sessionId, new WebAuthnChallenge(challenge, null, null, Instant.now().plus(2, ChronoUnit.MINUTES)));
        return PublicKeyCredentialRequestOptions.create(Base64Url.encode(challenge), properties.getRpId(), 120000, "required");
    }

    public WebAuthnAssertionResult finishAuthentication(String sessionId, WebAuthnAssertionRequest request, String origin) {
        WebAuthnChallenge challenge = challengeStore.consumeAuthentication(sessionId);
        if (challenge == null) {
            throw new WebAuthnException("Missing challenge");
        }
        byte[] authenticatorDataBytes = Base64Url.decode(request.response().authenticatorData());
        byte[] clientData = Base64Url.decode(request.response().clientDataJSON());
        byte[] signature = Base64Url.decode(request.response().signature());
        byte[] credentialId = Base64Url.decode(request.rawId());

        validateClientData(clientData, challenge.challenge(), origin, "webauthn.get");
        AuthenticatorData authenticatorData = authenticatorDataConverter.convert(authenticatorDataBytes);
        verifyRpIdHash(authenticatorData.getRpIdHash());
        if (!authenticatorData.isFlagUV()) {
            throw new WebAuthnException("User verification required");
        }
        DeviceBoundPolicy.enforce(authenticatorData);

        WebAuthnCredentialEntity credential = credentialRepository.findByCredentialId(Base64Url.encode(credentialId))
                .orElseThrow(() -> new WebAuthnException("Unknown credential"));

        verifyAssertionSignature(credential, authenticatorDataBytes, clientData, signature);
        credential.setSignCount(authenticatorData.getSignCount());
        credential.setLastUsedAt(Instant.now());
        credentialRepository.save(credential);
        return new WebAuthnAssertionResult(credential.getUser().getId(), credential.getUser().getMobileNumber());
    }

    public void verifyAssertionForUser(WebAuthnAssertionRequest request, String origin, byte[] challenge, Long userId) {
        byte[] authenticatorDataBytes = Base64Url.decode(request.response().authenticatorData());
        byte[] clientData = Base64Url.decode(request.response().clientDataJSON());
        byte[] signature = Base64Url.decode(request.response().signature());
        byte[] credentialId = Base64Url.decode(request.rawId());

        validateClientData(clientData, challenge, origin, "webauthn.get");
        AuthenticatorData authenticatorData = authenticatorDataConverter.convert(authenticatorDataBytes);
        verifyRpIdHash(authenticatorData.getRpIdHash());
        if (!authenticatorData.isFlagUV()) {
            throw new WebAuthnException("User verification required");
        }
        DeviceBoundPolicy.enforce(authenticatorData);

        WebAuthnCredentialEntity credential = credentialRepository.findByCredentialId(Base64Url.encode(credentialId))
                .orElseThrow(() -> new WebAuthnException("Unknown credential"));
        if (!credential.getUser().getId().equals(userId)) {
            throw new WebAuthnException("Credential does not belong to user");
        }
        verifyAssertionSignature(credential, authenticatorDataBytes, clientData, signature);
        credential.setSignCount(authenticatorData.getSignCount());
        credential.setLastUsedAt(Instant.now());
        credentialRepository.save(credential);
    }

    private void validateClientData(byte[] clientData, byte[] challenge, String origin, String type) {
        try {
            JsonNode node = objectMapper.readTree(clientData);
            String challengeB64 = node.get("challenge").asText();
            String clientOrigin = node.get("origin").asText();
            String clientType = node.get("type").asText();
            if (!Base64Url.encode(challenge).equals(challengeB64)) {
                throw new WebAuthnException("Challenge mismatch");
            }
            if (!properties.getOrigins().contains(clientOrigin)) {
                throw new WebAuthnException("Origin not allowed");
            }
            if (!type.equals(clientType)) {
                throw new WebAuthnException("Client data type mismatch");
            }
        } catch (Exception ex) {
            throw new WebAuthnException("Invalid client data", ex);
        }
    }

    private void verifyRpIdHash(byte[] rpIdHash) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] expected = digest.digest(properties.getRpId().getBytes(StandardCharsets.UTF_8));
            if (!MessageDigest.isEqual(expected, rpIdHash)) {
                throw new WebAuthnException("rpId hash mismatch");
            }
        } catch (Exception ex) {
            throw new WebAuthnException("rpId verification failed", ex);
        }
    }

    private void verifyAssertionSignature(WebAuthnCredentialEntity credential, byte[] authenticatorDataBytes, byte[] clientData, byte[] signature) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] clientDataHash = digest.digest(clientData);
            byte[] signedBytes = new byte[authenticatorDataBytes.length + clientDataHash.length];
            System.arraycopy(authenticatorDataBytes, 0, signedBytes, 0, authenticatorDataBytes.length);
            System.arraycopy(clientDataHash, 0, signedBytes, authenticatorDataBytes.length, clientDataHash.length);

            byte[] coseKey = Base64Url.decode(credential.getPublicKey());
            var decoded = CoseKeyDecoder.decode(coseKey);
            java.security.PublicKey publicKey = decoded.getPublicKey();
            Signature verifier = Signature.getInstance(selectSignatureAlgorithm(publicKey));
            verifier.initVerify(publicKey);
            verifier.update(signedBytes);
            if (!verifier.verify(signature)) {
                throw new WebAuthnException("Invalid signature");
            }
        } catch (Exception ex) {
            throw new WebAuthnException("Signature verification failed", ex);
        }
    }

    private String selectSignatureAlgorithm(java.security.PublicKey publicKey) {
        if (publicKey.getAlgorithm().equalsIgnoreCase("EC")) {
            return "SHA256withECDSA";
        }
        return "SHA256withRSA";
    }

    private byte[] randomChallenge() {
        byte[] challenge = new byte[32];
        secureRandom.nextBytes(challenge);
        return challenge;
    }

    public static Set<AuthenticatorTransport> parseTransports(List<String> transports) {
        if (transports == null || transports.isEmpty()) {
            return Set.of();
        }
        return transports.stream().map(AuthenticatorTransport::create).collect(Collectors.toSet());
    }
}
