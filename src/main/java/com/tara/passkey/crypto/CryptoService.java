package com.tara.passkey.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tara.passkey.config.CryptoProperties;
import com.github.benmanes.caffeine.cache.Cache;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.MGF1ParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.cache.CacheManager;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
public class CryptoService {
    public static final String REQUEST_CONTEXT_ATTR = "REQUEST_CRYPTO_CONTEXT";
    private static final String HMAC_ALGO = "HmacSHA256";
    private static final String AES_ALGO = "AES";
    private static final String RSA_ALGO = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final Duration TIMESTAMP_SKEW = Duration.ofMinutes(2);

    private final ObjectMapper objectMapper;
    private final CryptoProperties properties;
    private final Cache<String, String> replayCache;
    private final SecureRandom secureRandom = new SecureRandom();
    private final KeyPair keyPair;

    public CryptoService(ObjectMapper objectMapper, CryptoProperties properties, CacheManager cacheManager) {
        this.objectMapper = objectMapper;
        this.properties = properties;
        this.replayCache = (Cache<String, String>) cacheManager.getCache("replayCache").getNativeCache();
        this.keyPair = loadOrCreateKeyPair();
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    public String getPublicKeyPem() {
        String encoded = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + encoded + "\n-----END PUBLIC KEY-----\n";
    }

    public DecryptedEnvelope decryptEnvelope(byte[] requestBody, String path) throws IOException {
        EnvelopeRequest envelope = objectMapper.readValue(requestBody, EnvelopeRequest.class);
        validateEnvelopeHeader(envelope, path);
        byte[] keyMaterial = unwrapKeyMaterial(envelope.getEk());
        SecretKey aesKey = new SecretKeySpec(keyMaterial, 0, 32, AES_ALGO);
        SecretKey macKey = new SecretKeySpec(keyMaterial, 32, 32, HMAC_ALGO);
        verifyMac(envelope, macKey);
        byte[] plaintext = decryptAes(envelope.getIv(), envelope.getCt(), aesKey);
        RequestCryptoContext context = new RequestCryptoContext(envelope.getRequestId(), envelope.getPath(), aesKey, macKey);
        return new DecryptedEnvelope(plaintext, context);
    }

    public EnvelopeResponse encryptResponse(String requestId, String path, int status, byte[] plaintext, SecretKey aesKey, SecretKey macKey) {
        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);
        byte[] ciphertext = encryptAes(iv, plaintext, aesKey);
        EnvelopeResponse response = new EnvelopeResponse();
        response.setV(1);
        response.setRequestId(requestId);
        response.setTs(Instant.now().toEpochMilli());
        response.setStatus(status);
        response.setIv(Base64.getEncoder().encodeToString(iv));
        response.setCt(Base64.getEncoder().encodeToString(ciphertext));
        response.setMac(Base64.getEncoder().encodeToString(computeMac(1, requestId, path, response.getTs(), iv, ciphertext, macKey)));
        return response;
    }

    private void validateEnvelopeHeader(EnvelopeRequest envelope, String path) {
        if (envelope.getV() != 1) {
            throw new CryptoValidationException("Unsupported envelope version", HttpStatus.BAD_REQUEST);
        }
        if (!StringUtils.hasText(envelope.getRequestId())) {
            throw new CryptoValidationException("Missing requestId", HttpStatus.BAD_REQUEST);
        }
        if (!StringUtils.hasText(envelope.getPath()) || !envelope.getPath().equals(path)) {
            throw new CryptoValidationException("Path mismatch", HttpStatus.BAD_REQUEST);
        }
        Instant now = Instant.now();
        Instant ts = Instant.ofEpochMilli(envelope.getTs());
        if (ts.isBefore(now.minus(TIMESTAMP_SKEW)) || ts.isAfter(now.plus(TIMESTAMP_SKEW))) {
            throw new CryptoValidationException("Timestamp skew", HttpStatus.UNAUTHORIZED);
        }
        if (replayCache.getIfPresent(envelope.getRequestId()) != null) {
            throw new CryptoValidationException("Replay detected", HttpStatus.UNAUTHORIZED);
        }
        replayCache.put(envelope.getRequestId(), "1");
    }

    private void verifyMac(EnvelopeRequest envelope, SecretKey macKey) {
        byte[] iv = Base64.getDecoder().decode(envelope.getIv());
        byte[] ciphertext = Base64.getDecoder().decode(envelope.getCt());
        byte[] expected = computeMac(envelope.getV(), envelope.getRequestId(), envelope.getPath(), envelope.getTs(), iv, ciphertext, macKey);
        byte[] actual = Base64.getDecoder().decode(envelope.getMac());
        if (!MessageDigestUtil.constantTimeEquals(expected, actual)) {
            throw new CryptoValidationException("Invalid MAC", HttpStatus.UNAUTHORIZED);
        }
    }

    private byte[] computeMac(int version, String requestId, String path, long ts, byte[] iv, byte[] ciphertext, SecretKey macKey) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGO);
            mac.init(macKey);
            mac.update(ByteBuffer.allocate(4).putInt(version).array());
            mac.update(requestId.getBytes(StandardCharsets.UTF_8));
            mac.update(path.getBytes(StandardCharsets.UTF_8));
            mac.update(ByteBuffer.allocate(Long.BYTES).putLong(ts).array());
            mac.update(iv);
            mac.update(ciphertext);
            return mac.doFinal();
        } catch (Exception ex) {
            throw new CryptoValidationException("MAC failure", HttpStatus.INTERNAL_SERVER_ERROR, ex);
        }
    }

    private byte[] decryptAes(String ivB64, String ctB64, SecretKey aesKey) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(Base64.getDecoder().decode(ivB64)));
            return cipher.doFinal(Base64.getDecoder().decode(ctB64));
        } catch (Exception ex) {
            throw new CryptoValidationException("Decrypt failure", HttpStatus.BAD_REQUEST, ex);
        }
    }

    private byte[] encryptAes(byte[] iv, byte[] plaintext, SecretKey aesKey) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
            return cipher.doFinal(plaintext);
        } catch (Exception ex) {
            throw new CryptoValidationException("Encrypt failure", HttpStatus.INTERNAL_SERVER_ERROR, ex);
        }
    }

    private byte[] unwrapKeyMaterial(String ek) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_ALGO);
            OAEPParameterSpec oaepParams = new OAEPParameterSpec(
                    "SHA-256",
                    "MGF1",
                    MGF1ParameterSpec.SHA256,
                    PSource.PSpecified.DEFAULT
            );
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate(), oaepParams);
            return cipher.doFinal(Base64.getDecoder().decode(ek));
        } catch (Exception ex) {
            throw new CryptoValidationException("Key unwrap failure", HttpStatus.UNAUTHORIZED, ex);
        }
    }

    private KeyPair loadOrCreateKeyPair() {
        Path path = Path.of(properties.getKeyStorePath());
        if (Files.exists(path)) {
            try (InputStream inputStream = Files.newInputStream(path)) {
                KeyStore keyStore = KeyStore.getInstance("PKCS12");
                keyStore.load(inputStream, properties.getKeyStorePassword().toCharArray());
                PrivateKey privateKey = (PrivateKey) keyStore.getKey(properties.getKeyAlias(), properties.getKeyStorePassword().toCharArray());
                PublicKey publicKey = keyStore.getCertificate(properties.getKeyAlias()).getPublicKey();
                return new KeyPair(publicKey, privateKey);
            } catch (Exception ex) {
                throw new IllegalStateException("Unable to load keystore", ex);
            }
        }
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to generate RSA key", ex);
        }
    }

    public static final class DecryptedEnvelope {
        private final byte[] plaintext;
        private final RequestCryptoContext context;

        public DecryptedEnvelope(byte[] plaintext, RequestCryptoContext context) {
            this.plaintext = plaintext;
            this.context = context;
        }

        public byte[] getPlaintext() {
            return plaintext;
        }

        public RequestCryptoContext getContext() {
            return context;
        }
    }
}
