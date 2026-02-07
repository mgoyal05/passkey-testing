package com.tara.passkey.repository;

import com.tara.passkey.model.WebAuthnCredentialEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface WebAuthnCredentialRepository extends JpaRepository<WebAuthnCredentialEntity, Long> {
    Optional<WebAuthnCredentialEntity> findByCredentialId(String credentialId);
}
