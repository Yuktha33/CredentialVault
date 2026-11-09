package com.Credential.Vault.repository;
import com.Credential.Vault.entity.TwoFactorOtp;
import com.Credential.Vault.entity.User;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface TwoFactorOtpRepository
        extends JpaRepository<TwoFactorOtp, Long> {

    Optional<TwoFactorOtp> findTopByUserOrderByCreatedAtDesc(User user);


    Optional<TwoFactorOtp> findTopByUserAndPurposeOrderByCreatedAtDesc(
            User user,
            String purpose
    );

    void deleteByUser(User user);
    void deleteByUserAndPurpose(User user, String purpose);
}
