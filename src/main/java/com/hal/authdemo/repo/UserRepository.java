package com.hal.authdemo.repo;

import com.hal.authdemo.model.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);
    Optional<User> findByPhoneNumber(String phoneNumber);
    Optional<User> findByVerificationToken(String token);
    Optional<User> findByRefreshToken(String refreshToken);
    boolean existsByEmail(String email);
    boolean existsByPhoneNumber(String phoneNumber);
}
