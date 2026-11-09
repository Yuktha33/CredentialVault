package com.Credential.Vault.controller;
import com.Credential.Vault.dto.CredentialShareHistoryResponse;
import com.Credential.Vault.dto.ShareCredentialRequest;
import com.Credential.Vault.dto.SharedCredentialResponse;
import com.Credential.Vault.entity.User;
import com.Credential.Vault.repository.UserRepository;
import com.Credential.Vault.service.CredentialShareService;

import jakarta.validation.Valid;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/shares")
@CrossOrigin(origins = {
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "http://localhost:63342"
})
public class CredentialShareController {

    private final CredentialShareService shareService;
    private final UserRepository userRepository;

    public CredentialShareController(
            CredentialShareService shareService,
            UserRepository userRepository) {
        this.shareService = shareService;
        this.userRepository = userRepository;
    }

    private User getLoggedInUser(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new IllegalArgumentException("User is not authenticated");
        }

        String email = authentication.getName();

        return userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new IllegalArgumentException("User not found"));
    }

    // Share a credential
    @PostMapping("/{credentialId}")
    public ResponseEntity<?> shareCredential(
            @PathVariable Long credentialId,
            @Valid @RequestBody ShareCredentialRequest request,
            Authentication authentication) {

        User owner = getLoggedInUser(authentication);

        shareService.shareCredential(credentialId, owner, request);

        return ResponseEntity.ok("Credential shared successfully");
    }

    // View credentials shared with the logged-in user
    @GetMapping("/received")
    public ResponseEntity<List<SharedCredentialResponse>> getSharedCredentials(
            Authentication authentication) {

        User recipient = getLoggedInUser(authentication);

        return ResponseEntity.ok(
                shareService.getSharedCredentials(recipient));
    }

    // Revoke sharing access
    @DeleteMapping("/{shareId}")
    public ResponseEntity<?> revokeSharing(
            @PathVariable Long shareId,
            Authentication authentication) {

        User owner = getLoggedInUser(authentication);

        shareService.revokeSharing(shareId, owner);

        return ResponseEntity.ok("Sharing access revoked successfully");
    }
    // View sharing history of the logged-in owner
    @GetMapping("/history")
    public ResponseEntity<List<CredentialShareHistoryResponse>> getSharingHistory(
            Authentication authentication) {

        User owner = getLoggedInUser(authentication);

        return ResponseEntity.ok(
                shareService.getSharingHistory(owner));
    }
}
