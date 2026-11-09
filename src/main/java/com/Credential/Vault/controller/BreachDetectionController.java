
package com.Credential.Vault.controller;

import com.Credential.Vault.service.BreachDetectionService;
import com.Credential.Vault.service.BreachDetectionService.ScanResult;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/user/breach")
@PreAuthorize("hasAnyRole('ADMIN', 'MANAGER', 'USER')")
public class BreachDetectionController {

    private final BreachDetectionService breachDetectionService;

    public BreachDetectionController(
            BreachDetectionService breachDetectionService) {
        this.breachDetectionService = breachDetectionService;
    }

    @PostMapping("/scan")
    public ResponseEntity<List<ScanResult>> scan(
            Authentication authentication) {

        String email = authentication.getName();

        List<ScanResult> results =
                breachDetectionService.scanPasswords(email);

        return ResponseEntity.ok(results);
    }
}
