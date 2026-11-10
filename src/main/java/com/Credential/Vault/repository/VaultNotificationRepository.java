
package com.Credential.Vault.repository;

import com.Credential.Vault.entity.User;
import com.Credential.Vault.entity.VaultNotification;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface VaultNotificationRepository
        extends JpaRepository<VaultNotification, Long> {


    @EntityGraph(attributePaths = "credential")
    List<VaultNotification> findByUserOrderByCreatedAtDesc(User user);


    long countByUserAndReadFalse(User user);


    boolean existsByUserAndCredentialIdAndScanId(
            User user,
            Long credentialId,
            String scanId
    );


    @EntityGraph(attributePaths = "credential")
    Optional<VaultNotification> findByIdAndUser(
            Long id,
            User user
    );


    @EntityGraph(attributePaths = {"user", "credential"})
    List<VaultNotification> findAllByOrderByCreatedAtDesc();
}
