package com.tara.passkey.webauthn;

import com.github.benmanes.caffeine.cache.Cache;
import java.time.Instant;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Component;

@Component
public class WebAuthnChallengeStore {
    private final Cache<String, WebAuthnChallenge> cache;

    public WebAuthnChallengeStore(CacheManager cacheManager) {
        this.cache = (Cache<String, WebAuthnChallenge>) cacheManager.getCache("webauthnChallenge").getNativeCache();
    }

    public void saveRegistration(String sessionId, WebAuthnChallenge challenge) {
        cache.put("reg:" + sessionId, challenge);
    }

    public WebAuthnChallenge consumeRegistration(String sessionId) {
        return consume("reg:" + sessionId);
    }

    public void saveAuthentication(String sessionId, WebAuthnChallenge challenge) {
        cache.put("auth:" + sessionId, challenge);
    }

    public WebAuthnChallenge consumeAuthentication(String sessionId) {
        return consume("auth:" + sessionId);
    }

    private WebAuthnChallenge consume(String key) {
        WebAuthnChallenge challenge = cache.getIfPresent(key);
        if (challenge != null && challenge.expiresAt().isAfter(Instant.now())) {
            cache.invalidate(key);
            return challenge;
        }
        cache.invalidate(key);
        return null;
    }
}
