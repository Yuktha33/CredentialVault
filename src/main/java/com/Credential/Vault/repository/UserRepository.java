
package com.Credential.Vault.repository;

import com.Credential.Vault.entity.User;
import com.Credential.Vault.entity.Role;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

    boolean existsByEmail(String email);

    // Retrieve all users with a particular role
    List<User> findByRole(Role role);
}
