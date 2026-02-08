package com.tara.passkey.repository;

import com.tara.passkey.model.UserEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Long> {
    Optional<UserEntity> findByMobileNumber(String mobileNumber);
}
