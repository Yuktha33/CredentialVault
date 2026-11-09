
package com.Credential.Vault.controller;

import com.Credential.Vault.dto.CreateCredentialRequest;
import com.Credential.Vault.dto.UpdateCredentialRequest;
import com.Credential.Vault.dto.CredentialResponse;
import com.Credential.Vault.service.CredentialService;

import jakarta.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/user/credentials")
@PreAuthorize("hasAnyRole('ADMIN', 'MANAGER', 'USER')")
public class CredentialController {

    private final CredentialService credentialService;

    public CredentialController(CredentialService credentialService) {
        this.credentialService = credentialService;
    }

    // 1. Save a new credential
    @PostMapping
    public ResponseEntity<CredentialResponse> createCredential(
            @Valid @RequestBody CreateCredentialRequest request,
            Authentication authentication) {

        CredentialResponse response =
                credentialService.saveCredential(
                        request,
                        authentication.getName()
                );

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(response);
    }

    // 2. Get all credentials of logged-in user
    @GetMapping
    public ResponseEntity<List<CredentialResponse>> getAllCredentials(
            Authentication authentication) {

        return ResponseEntity.ok(
                credentialService.getAllCredentials(
                        authentication.getName()
                )
        );
    }

    // 3. Get one credential
    @GetMapping("/{id}")
    public ResponseEntity<CredentialResponse> getCredentialById(
            @PathVariable Long id,
            Authentication authentication) {

        return ResponseEntity.ok(
                credentialService.getCredentialById(
                        id,
                        authentication.getName()
                )
        );
    }

    // 4. Update a credential
    @PutMapping("/{id}")
    public ResponseEntity<CredentialResponse> updateCredential(
            @PathVariable Long id,
            @Valid @RequestBody UpdateCredentialRequest request,
            Authentication authentication) {

        return ResponseEntity.ok(
                credentialService.updateCredential(
                        id,
                        request,
                        authentication.getName()
                )
        );
    }

    // 5. Delete a credential
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteCredential(
            @PathVariable Long id,
            Authentication authentication) {

        credentialService.deleteCredential(
                id,
                authentication.getName()
        );

        return ResponseEntity.noContent().build();
    }
}
