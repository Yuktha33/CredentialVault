
package com.Credential.Vault.service;

import com.Credential.Vault.dto.CredentialShareHistoryResponse;
import com.Credential.Vault.dto.ShareCredentialRequest;
import com.Credential.Vault.dto.SharedCredentialResponse;
import com.Credential.Vault.entity.Credential;
import com.Credential.Vault.entity.CredentialShare;
import com.Credential.Vault.entity.User;
import com.Credential.Vault.repository.CredentialRepository;
import com.Credential.Vault.repository.CredentialShareRepository;
import com.Credential.Vault.repository.UserRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Locale;

@Service
public class CredentialShareService {

    private final CredentialShareRepository shareRepository;
    private final CredentialRepository credentialRepository;
    private final UserRepository userRepository;
    private final EncryptionService encryptionService;

    public CredentialShareService(
            CredentialShareRepository shareRepository,
            CredentialRepository credentialRepository,
            UserRepository userRepository,
            EncryptionService encryptionService) {

        this.shareRepository = shareRepository;
        this.credentialRepository = credentialRepository;
        this.userRepository = userRepository;
        this.encryptionService = encryptionService;
    }

    // =========================================
    // 1. SHARE CREDENTIAL
    // =========================================

    @Transactional
    public CredentialShare shareCredential(
            Long credentialId,
            User owner,
            ShareCredentialRequest request) {

        if (owner == null || owner.getId() == null) {
            throw new IllegalArgumentException("Invalid owner");
        }

        if (!Boolean.TRUE.equals(owner.getActive())) {
            throw new IllegalArgumentException("Account is inactive");
        }

        // Validate permission
        String permission = request.getPermission()
                .trim()
                .toUpperCase(Locale.ROOT);

        if (!permission.equals("VIEW")
                && !permission.equals("EDIT")) {
            throw new IllegalArgumentException(
                    "Permission must be VIEW or EDIT"
            );
        }

        // Find credential belonging to owner
        Credential credential = credentialRepository
                .findByIdAndOwner(credentialId, owner)
                .orElseThrow(() ->
                        new IllegalArgumentException(
                                "Credential not found or access denied"
                        )
                );

        // Find recipient
        String recipientEmail = request.getRecipientEmail()
                .trim()
                .toLowerCase(Locale.ROOT);

        User recipient = userRepository.findByEmail(recipientEmail)
                .orElseThrow(() ->
                        new IllegalArgumentException(
                                "Recipient account not found"
                        )
                );

        if (!Boolean.TRUE.equals(recipient.getActive())) {
            throw new IllegalArgumentException(
                    "Recipient account is inactive"
            );
        }

        // Prevent sharing with yourself
        if (owner.getId().equals(recipient.getId())) {
            throw new IllegalArgumentException(
                    "You cannot share credentials with yourself"
            );
        }

        // Prevent duplicate active sharing
        boolean alreadyShared =
                shareRepository
                        .existsByCredentialIdAndSharedWithIdAndStatus(
                                credentialId,
                                recipient.getId(),
                                "ACTIVE"
                        );

        if (alreadyShared) {
            throw new IllegalArgumentException(
                    "This credential is already shared with this user"
            );
        }

        // Create sharing record
        CredentialShare share = new CredentialShare();

        share.setCredential(credential);
        share.setSharedBy(owner);
        share.setSharedWith(recipient);
        share.setPermission(permission);
        share.setStatus("ACTIVE");

        return shareRepository.save(share);
    }


    // =========================================
    // 2. GET CREDENTIALS SHARED WITH USER
    // =========================================

    @Transactional(readOnly = true)
    public List<SharedCredentialResponse> getSharedCredentials(
            User recipient) {

        if (recipient == null || recipient.getId() == null) {
            throw new IllegalArgumentException("Invalid user");
        }

        if (!Boolean.TRUE.equals(recipient.getActive())) {
            throw new IllegalArgumentException("Account is inactive");
        }

        List<CredentialShare> shares =
                shareRepository.findBySharedWithIdAndStatus(
                        recipient.getId(),
                        "ACTIVE"
                );

        return shares.stream()
                .filter(share ->
                        Boolean.TRUE.equals(
                                share.getSharedBy().getActive()
                        )
                )
                .map(this::mapToResponse)
                .toList();
    }


    // =========================================
    // 3. MAP AND DECRYPT SHARED CREDENTIAL
    // =========================================

    private SharedCredentialResponse mapToResponse(
            CredentialShare share) {

        Credential credential = share.getCredential();

        SharedCredentialResponse response =
                new SharedCredentialResponse();

        response.setShareId(share.getId());
        response.setCredentialId(credential.getId());

        response.setTitle(credential.getTitle());
        response.setWebsite(credential.getWebsite());
        response.setCategory(credential.getCategory());

        // Decrypt only after retrieving an authorized active share
        response.setUsername(
                encryptionService.decrypt(credential.getUsername())
        );

        response.setPassword(
                encryptionService.decrypt(
                        credential.getEncryptedPassword()
                )
        );

        response.setNotes(
                encryptionService.decrypt(credential.getNotes())
        );

        response.setOwnerName(
                share.getSharedBy().getName()
        );

        response.setOwnerEmail(
                share.getSharedBy().getEmail()
        );

        response.setPermission(share.getPermission());
        response.setSharedAt(share.getSharedAt());

        return response;
    }


    // =========================================
    // 4. REVOKE SHARED CREDENTIAL
    // =========================================

    @Transactional
    public void revokeSharing(Long shareId, User owner) {

        if (owner == null || owner.getId() == null) {
            throw new IllegalArgumentException("Invalid owner");
        }

        CredentialShare share = shareRepository.findById(shareId)
                .orElseThrow(() ->
                        new IllegalArgumentException(
                                "Sharing record not found"
                        )
                );

        // Only the original owner can revoke access
        if (!share.getSharedBy().getId().equals(owner.getId())) {
            throw new IllegalArgumentException(
                    "You are not authorized to revoke this sharing"
            );
        }

        if (!"ACTIVE".equals(share.getStatus())) {
            throw new IllegalArgumentException(
                    "Sharing is already revoked"
            );
        }

        share.setStatus("REVOKED");
        share.setRevokedAt(LocalDateTime.now());

        shareRepository.save(share);
    }


    // =========================================
    // 5. GET SHARES CREATED BY OWNER
    // =========================================

    @Transactional(readOnly = true)
    public List<CredentialShare> getMySharedCredentials(User owner) {

        return shareRepository.findBySharedByIdAndStatus(
                owner.getId(),
                "ACTIVE"
        );
    }
    @Transactional(readOnly = true)
    public List<CredentialShareHistoryResponse> getSharingHistory(User owner) {

        if (owner == null || owner.getId() == null) {
            throw new IllegalArgumentException("Invalid owner");
        }

        List<CredentialShare> shares =
                shareRepository.findBySharedById(owner.getId());

        return shares.stream().map(share -> {

            CredentialShareHistoryResponse response =
                    new CredentialShareHistoryResponse();

            response.setShareId(share.getId());
            response.setCredentialId(share.getCredential().getId());
            response.setCredentialTitle(share.getCredential().getTitle());

            response.setRecipientName(share.getSharedWith().getName());
            response.setRecipientEmail(share.getSharedWith().getEmail());

            response.setPermission(share.getPermission());
            response.setStatus(share.getStatus());

            response.setSharedAt(share.getSharedAt());
            response.setRevokedAt(share.getRevokedAt());

            return response;

        }).toList();
    }
}
