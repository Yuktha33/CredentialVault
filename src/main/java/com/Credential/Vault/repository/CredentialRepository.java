
package com.Credential.Vault.repository;

import com.Credential.Vault.entity.Credential;
import com.Credential.Vault.entity.User;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface CredentialRepository
        extends JpaRepository<Credential, Long> {

    // Get credentials belonging to a particular user
    List<Credential> findByOwner(User owner);

    // Find a credential only if it belongs to that user
    Optional<Credential> findByIdAndOwner(Long id, User owner);

    // Count credentials belonging to a user
    long countByOwner(User owner);

    List<Credential> findByOwnerOrderByCreatedAtDesc(User owner);
}
