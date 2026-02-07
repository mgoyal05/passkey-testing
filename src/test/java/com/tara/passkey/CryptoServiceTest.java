package com.tara.passkey;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tara.passkey.config.CryptoProperties;
import com.tara.passkey.crypto.CryptoService;
import com.tara.passkey.crypto.EnvelopeRequest;
import com.tara.passkey.crypto.RequestCryptoContext;
import com.tara.passkey.crypto.CryptoService.DecryptedEnvelope;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.springframework.cache.CacheManager;
import org.springframework.cache.caffeine.CaffeineCacheManager;

import static org.assertj.core.api.Assertions.assertThat;

public class CryptoServiceTest {

    @Test
    void decryptsRoundTripEnvelope() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        CryptoProperties properties = new CryptoProperties();
        Path tempDir = Files.createTempDirectory("keystore");
        properties.setKeyStorePath(tempDir.resolve("keystore.p12").toString());

        CaffeineCacheManager cacheManager = new CaffeineCacheManager("replayCache");
        cacheManager.setCaffeine(Caffeine.newBuilder());
        CryptoService cryptoService = new CryptoService(mapper, properties, cacheManager);

        String path = "/api/otp/send";
        String requestId = "req-123";
        long ts = Instant.now().toEpochMilli();
        byte[] keyMaterial = new byte[64];
        java.security.SecureRandom.getInstanceStrong().nextBytes(keyMaterial);
        SecretKey aesKey = new SecretKeySpec(keyMaterial, 0, 32, "AES");
        SecretKey macKey = new SecretKeySpec(keyMaterial, 32, 32, "HmacSHA256");
        byte[] iv = new byte[16];
        java.security.SecureRandom.getInstanceStrong().nextBytes(iv);

        byte[] plaintext = "{\"hello\":\"world\"}".getBytes(StandardCharsets.UTF_8);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] ct = cipher.doFinal(plaintext);

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(macKey);
        mac.update(java.nio.ByteBuffer.allocate(4).putInt(1).array());
        mac.update(requestId.getBytes(StandardCharsets.UTF_8));
        mac.update(path.getBytes(StandardCharsets.UTF_8));
        mac.update(java.nio.ByteBuffer.allocate(Long.BYTES).putLong(ts).array());
        mac.update(iv);
        mac.update(ct);
        byte[] macBytes = mac.doFinal();

        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsa.init(Cipher.ENCRYPT_MODE, cryptoService.getPublicKey());
        byte[] ek = rsa.doFinal(keyMaterial);

        EnvelopeRequest envelope = new EnvelopeRequest();
        envelope.setV(1);
        envelope.setRequestId(requestId);
        envelope.setTs(ts);
        envelope.setPath(path);
        envelope.setIv(Base64.getEncoder().encodeToString(iv));
        envelope.setCt(Base64.getEncoder().encodeToString(ct));
        envelope.setMac(Base64.getEncoder().encodeToString(macBytes));
        envelope.setEk(Base64.getEncoder().encodeToString(ek));

        byte[] requestBytes = mapper.writeValueAsBytes(envelope);
        DecryptedEnvelope decrypted = cryptoService.decryptEnvelope(requestBytes, path);
        assertThat(new String(decrypted.getPlaintext(), StandardCharsets.UTF_8)).contains("hello");
        RequestCryptoContext context = decrypted.getContext();
        assertThat(context.getRequestId()).isEqualTo(requestId);
    }
}
