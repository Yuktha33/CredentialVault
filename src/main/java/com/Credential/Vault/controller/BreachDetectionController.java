
package com.Credential.Vault.controller;

import com.Credential.Vault.service.BreachDetectionService;
import com.Credential.Vault.service.BreachDetectionService.AdminScanResult;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/admin/breach")
@PreAuthorize("hasRole('ADMIN')")
public class BreachDetectionController {

    private final BreachDetectionService breachDetectionService;

    public BreachDetectionController(
            BreachDetectionService breachDetectionService) {
        this.breachDetectionService = breachDetectionService;
    }


    @PostMapping("/scan")
    public ResponseEntity<List<AdminScanResult>> scanAllUsers() {

        List<AdminScanResult> results =
                breachDetectionService.scanAllUsers();

        return ResponseEntity.ok(results);
    }
}
