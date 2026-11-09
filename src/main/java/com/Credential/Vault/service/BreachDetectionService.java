
package com.Credential.Vault.service;

import com.Credential.Vault.entity.Credential;
import com.Credential.Vault.entity.User;
import com.Credential.Vault.repository.CredentialRepository;
import com.Credential.Vault.repository.UserRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class BreachDetectionService {

    private final CredentialRepository credentialRepository;
    private final UserRepository userRepository;
    private final EncryptionService encryptionService;
    private final HIBPService hibpService;

    public BreachDetectionService(
            CredentialRepository credentialRepository,
            UserRepository userRepository,
            EncryptionService encryptionService,
            HIBPService hibpService) {

        this.credentialRepository = credentialRepository;
        this.userRepository = userRepository;
        this.encryptionService = encryptionService;
        this.hibpService = hibpService;
    }

    // Result returned to the frontend.
    public record ScanResult(
            Long credentialId,
            String title,
            String website,
            boolean breached,
            long occurrences,
            LocalDateTime scannedAt
    ) {}

    @Transactional(readOnly = true)
    public List<ScanResult> scanPasswords(String email) {

        // 1. Identify logged-in user.
        User user = userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new IllegalArgumentException("User not found"));

        // 2. Retrieve only this user's credentials.
        List<Credential> credentials =
                credentialRepository.findByOwnerOrderByCreatedAtDesc(user);

        List<ScanResult> results = new ArrayList<>();

        // Avoid checking duplicate passwords repeatedly.
        Map<String, HIBPService.BreachResult> cache =
                new HashMap<>();

        for (Credential credential : credentials) {

            // 3. Decrypt password inside backend only.
            String password = encryptionService.decrypt(
                    credential.getEncryptedPassword()
            );

            if (password == null || password.isEmpty()) {
                throw new IllegalStateException(
                        "Unable to scan credential ID: "
                                + credential.getId()
                );
            }

            // 4. Check HIBP, reusing duplicate password results.
            HIBPService.BreachResult breachResult =
                    cache.computeIfAbsent(
                            password,
                            hibpService::checkPassword
                    );

            // 5. Return metadata only, never the password.
            results.add(new ScanResult(
                    credential.getId(),
                    credential.getTitle(),
                    credential.getWebsite(),
                    breachResult.breached(),
                    breachResult.occurrences(),
                    LocalDateTime.now()
            ));
        }

        return results;
    }
}
