
package com.Credential.Vault.service;
import com.Credential.Vault.repository.CredentialShareRepository;
import com.Credential.Vault.dto.CreateCredentialRequest;
import com.Credential.Vault.dto.UpdateCredentialRequest;
import com.Credential.Vault.dto.CredentialResponse;

import com.Credential.Vault.entity.Credential;
import com.Credential.Vault.entity.User;

import com.Credential.Vault.repository.CredentialRepository;
import com.Credential.Vault.repository.UserRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional
public class CredentialService {

    private final CredentialRepository credentialRepository;
    private final UserRepository userRepository;
    private final EncryptionService encryptionService;
    private final CredentialShareRepository shareRepository;

    public CredentialService(
            CredentialRepository credentialRepository,
            UserRepository userRepository,
            EncryptionService encryptionService,
            CredentialShareRepository shareRepository) {

        this.credentialRepository = credentialRepository;
        this.userRepository = userRepository;
        this.encryptionService = encryptionService;
        this.shareRepository = shareRepository;
    }

    // ==========================================
    // 1. CREATE CREDENTIAL
    // ==========================================

    public CredentialResponse saveCredential(
            CreateCredentialRequest request,
            String email) {

        User owner = getUserByEmail(email);

        Credential credential = new Credential();

        credential.setTitle(request.getTitle());
        credential.setWebsite(request.getWebsite());

        // Category
        credential.setCategory(getCategory(request.getCategory()));

        // Encrypt sensitive information
        credential.setUsername(
                encryptionService.encrypt(request.getUsername())
        );

        credential.setEncryptedPassword(
                encryptionService.encrypt(request.getPassword())
        );

        credential.setNotes(
                encryptionService.encrypt(request.getNotes())
        );

        credential.setOwner(owner);

        Credential savedCredential =
                credentialRepository.save(credential);

        return mapToResponse(savedCredential);
    }

    // ==========================================
    // 2. GET ALL CREDENTIALS
    // ==========================================

    @Transactional(readOnly = true)
    public List<CredentialResponse> getAllCredentials(String email) {

        User owner = getUserByEmail(email);

        return credentialRepository
                .findByOwnerOrderByCreatedAtDesc(owner)
                .stream()
                .map(this::mapToResponse)
                .toList();
    }

    // ==========================================
    // 3. GET CREDENTIAL BY ID
    // ==========================================

    @Transactional(readOnly = true)
    public CredentialResponse getCredentialById(
            Long id,
            String email) {

        User owner = getUserByEmail(email);

        Credential credential = credentialRepository
                .findByIdAndOwner(id, owner)
                .orElseThrow(() ->
                        new IllegalArgumentException(
                                "Credential not found"
                        )
                );

        return mapToResponse(credential);
    }

    // ==========================================
    // 4. UPDATE CREDENTIAL
    // ==========================================

    public CredentialResponse updateCredential(
            Long id,
            UpdateCredentialRequest request,
            String email) {

        User user = getUserByEmail(email);

        // First check whether the logged-in user owns the credential
        Credential credential = credentialRepository
                .findByIdAndOwner(id, user)
                .orElse(null);

        // If not the owner, check whether it was shared with them
        if (credential == null) {

            var share = shareRepository
                    .findByCredentialIdAndSharedWithIdAndStatus(
                            id, user.getId(), "ACTIVE")
                    .orElseThrow(() ->
                            new IllegalArgumentException(
                                    "Credential not found or access denied"));

            // Check whether the original owner is active
            if (!Boolean.TRUE.equals(share.getSharedBy().getActive())) {
                throw new IllegalArgumentException(
                        "Credential owner account is inactive");
            }

            // Only EDIT permission allows modifications
            if (!"EDIT".equals(share.getPermission())) {
                throw new IllegalArgumentException(
                        "You have VIEW-only permission. Editing is not allowed.");
            }

            credential = share.getCredential();
        }

        // Update credential details
        credential.setTitle(request.getTitle());
        credential.setWebsite(request.getWebsite());
        credential.setCategory(getCategory(request.getCategory()));

        // Encrypt updated sensitive information
        credential.setUsername(
                encryptionService.encrypt(request.getUsername()));

        credential.setEncryptedPassword(
                encryptionService.encrypt(request.getPassword()));

        credential.setNotes(
                encryptionService.encrypt(request.getNotes()));

        Credential updatedCredential =
                credentialRepository.save(credential);

        return mapToResponse(updatedCredential);
    }
    // ==========================================
    // 5. DELETE CREDENTIAL
    // ==========================================

    public void deleteCredential(Long id, String email) {

        User owner = getUserByEmail(email);

        Credential credential = credentialRepository
                .findByIdAndOwner(id, owner)
                .orElseThrow(() ->
                        new IllegalArgumentException(
                                "Credential not found"
                        )
                );

        credentialRepository.delete(credential);
    }

    // ==========================================
    // 6. MAP ENTITY TO RESPONSE
    // ==========================================


    private CredentialResponse mapToResponse(Credential credential) {

        return new CredentialResponse(
                credential.getId(),
                credential.getTitle(),
                credential.getWebsite(),

                // Decrypt username
                encryptionService.decrypt(
                        credential.getUsername()
                ),

                // Decrypt password
                encryptionService.decrypt(
                        credential.getEncryptedPassword()
                ),

                // Decrypt notes
                encryptionService.decrypt(
                        credential.getNotes()
                ),

                // Category comes after notes
                credential.getCategory(),

                credential.getCreatedAt(),
                credential.getUpdatedAt()
        );
    }

    // ==========================================
    // 7. GET USER BY EMAIL
    // ==========================================

    private User getUserByEmail(String email) {

        return userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new IllegalArgumentException(
                                "User not found"
                        )
                );
    }

    // ==========================================
    // 8. DEFAULT CATEGORY
    // ==========================================

    private String getCategory(String category) {

        if (category == null || category.isBlank()) {
            return "Other";
        }

        return category.trim();
    }
}
