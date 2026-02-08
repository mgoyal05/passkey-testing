package com.tara.passkey;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tara.passkey.config.WebAuthnProperties;
import com.tara.passkey.repository.WebAuthnCredentialRepository;
import com.tara.passkey.service.UserService;
import com.tara.passkey.webauthn.PublicKeyCredentialCreationOptions;
import com.tara.passkey.webauthn.WebAuthnChallengeStore;
import com.tara.passkey.webauthn.WebAuthnService;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.cache.caffeine.CaffeineCacheManager;

import static org.assertj.core.api.Assertions.assertThat;

public class WebAuthnServiceTest {

    @Test
    void registrationOptionsContainRequiredFlags() {
        WebAuthnProperties props = new WebAuthnProperties();
        props.setRpId("localhost");
        props.setRpName("Tara");
        props.setOrigins(List.of("http://localhost:8080"));

        CaffeineCacheManager cacheManager = new CaffeineCacheManager("webauthnChallenge");
        cacheManager.setCaffeine(Caffeine.newBuilder());
        WebAuthnChallengeStore store = new WebAuthnChallengeStore(cacheManager);
        WebAuthnService service = new WebAuthnService(props,
                Mockito.mock(WebAuthnCredentialRepository.class),
                Mockito.mock(UserService.class),
                store,
                new ObjectMapper());

        PublicKeyCredentialCreationOptions options = service.startRegistration("sess", "+123", "Consumer");
        assertThat(options.getAuthenticatorSelection().residentKey()).isEqualTo("required");
        assertThat(options.getAuthenticatorSelection().userVerification()).isEqualTo("required");
        assertThat(options.getAuthenticatorSelection().authenticatorAttachment()).isEqualTo("platform");
    }
}
