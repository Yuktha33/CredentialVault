
package com.Credential.Vault.repository;

import com.Credential.Vault.entity.CredentialShare;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface CredentialShareRepository
        extends JpaRepository<CredentialShare, Long> {

    // Find active credentials shared with a user
    List<CredentialShare> findBySharedWithIdAndStatus(
            Long userId,
            String status
    );

    // Find all sharing records created by an owner
    List<CredentialShare> findBySharedById(Long ownerId);

    // Find sharing record for a particular credential and recipient
    Optional<CredentialShare> findByCredentialIdAndSharedWithId(
            Long credentialId,
            Long recipientId
    );

    // Find active sharing record
    Optional<CredentialShare> findByCredentialIdAndSharedWithIdAndStatus(
            Long credentialId,
            Long recipientId,
            String status
    );

    // Check whether an active share exists
    boolean existsByCredentialIdAndSharedWithIdAndStatus(
            Long credentialId,
            Long recipientId,
            String status
    );

    // Retrieve active shares for an owner
    List<CredentialShare> findBySharedByIdAndStatus(
            Long ownerId,
            String status
    );
}
