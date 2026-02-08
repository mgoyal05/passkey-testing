package com.tara.passkey.service;

import com.tara.passkey.model.UserEntity;
import com.tara.passkey.repository.UserRepository;
import java.time.Instant;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService {
    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Transactional
    public UserEntity getOrCreateUser(String mobileNumber, String customerType) {
        return userRepository.findByMobileNumber(mobileNumber)
                .orElseGet(() -> {
                    UserEntity user = new UserEntity();
                    user.setMobileNumber(mobileNumber);
                    user.setCustomerType(customerType);
                    user.setCreatedAt(Instant.now());
                    return userRepository.save(user);
                });
    }
}
