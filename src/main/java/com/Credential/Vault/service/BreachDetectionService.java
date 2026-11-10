
package com.Credential.Vault.service;

import com.Credential.Vault.entity.Credential;
import com.Credential.Vault.entity.User;
import com.Credential.Vault.entity.Role;

import com.Credential.Vault.repository.CredentialRepository;
import com.Credential.Vault.repository.UserRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

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

    // Result for individual user scanning
    public record ScanResult(
            Long credentialId,
            String title,
            String website,
            boolean breached,
            long occurrences,
            LocalDateTime scannedAt
    ) {}

    // Result for Admin global scanning
    public record AdminScanResult(
            Long userId,
            String userName,
            String userEmail,
            Long credentialId,
            String title,
            String website,
            boolean breached,
            long occurrences,
            LocalDateTime scannedAt,
            String scanId
    ) {}

    // ==========================================
    // USER-SPECIFIC BREACH SCAN
    // ==========================================

    @Transactional(readOnly = true)
    public List<ScanResult> scanPasswords(String email) {

        User user = userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new IllegalArgumentException("User not found"));

        List<Credential> credentials =
                credentialRepository.findByOwnerOrderByCreatedAtDesc(user);

        List<ScanResult> results = new ArrayList<>();

        Map<String, HIBPService.BreachResult> cache =
                new HashMap<>();

        LocalDateTime scanTime = LocalDateTime.now();

        for (Credential credential : credentials) {

            String password = encryptionService.decrypt(
                    credential.getEncryptedPassword()
            );

            if (password == null || password.isEmpty()) {
                throw new IllegalStateException(
                        "Unable to scan credential ID: "
                                + credential.getId()
                );
            }

            HIBPService.BreachResult breachResult =
                    cache.computeIfAbsent(
                            password,
                            hibpService::checkPassword
                    );

            results.add(new ScanResult(
                    credential.getId(),
                    credential.getTitle(),
                    credential.getWebsite(),
                    breachResult.breached(),
                    breachResult.occurrences(),
                    scanTime
            ));
        }

        return results;
    }

    // ==========================================
    // ADMIN GLOBAL BREACH SCAN
    // ==========================================

    @Transactional(readOnly = true)
    public List<AdminScanResult> scanAllUsers() {

        // Retrieve only regular USER accounts
        List<User> users = userRepository.findByRole(Role.USER);

        List<AdminScanResult> results = new ArrayList<>();

        // Reuse results for duplicate passwords
        Map<String, HIBPService.BreachResult> cache =
                new HashMap<>();

        LocalDateTime scanTime = LocalDateTime.now();

        // Generate a unique ID for this scan
        String scanId = UUID.randomUUID().toString();

        for (User user : users) {

            // Retrieve credentials belonging to this user
            List<Credential> credentials =
                    credentialRepository
                            .findByOwnerOrderByCreatedAtDesc(user);

            for (Credential credential : credentials) {

                // Decrypt only inside backend memory
                String password = encryptionService.decrypt(
                        credential.getEncryptedPassword()
                );

                if (password == null || password.isEmpty()) {
                    throw new IllegalStateException(
                            "Unable to scan credential ID: "
                                    + credential.getId()
                    );
                }

                // Check password against HIBP
                HIBPService.BreachResult breachResult =
                        cache.computeIfAbsent(
                                password,
                                hibpService::checkPassword
                        );

                // Return metadata only
                results.add(new AdminScanResult(
                        user.getId(),
                        user.getName(),
                        user.getEmail(),
                        credential.getId(),
                        credential.getTitle(),
                        credential.getWebsite(),
                        breachResult.breached(),
                        breachResult.occurrences(),
                        scanTime,
                        scanId
                ));
            }
        }

        return results;
    }
}
