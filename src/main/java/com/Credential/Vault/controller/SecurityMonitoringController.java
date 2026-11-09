
package com.Credential.Vault.controller;

import com.Credential.Vault.entity.SecurityEvent;
import com.Credential.Vault.repository.SecurityEventRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/admin/security")
public class SecurityMonitoringController {

    private final SecurityEventRepository securityEventRepository;

    public SecurityMonitoringController(
            SecurityEventRepository securityEventRepository) {
        this.securityEventRepository = securityEventRepository;
    }

    @GetMapping("/stats")
    public Map<String, Object> getSecurityStats() {

        long successfulLogins =
                securityEventRepository.countByEventTypeAndStatus(
                        "LOGIN", "SUCCESS");

        long failedLogins =
                securityEventRepository.countByEventTypeAndStatus(
                        "LOGIN", "FAILED");

        long totalEvents = securityEventRepository.count();

        long suspiciousActivity =
                securityEventRepository
                        .countByEventTypeAndStatus(
                                "SUSPICIOUS_LOGIN",
                                "DETECTED"
                        );



        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("successfulLogins", successfulLogins);
        stats.put("failedLogins", failedLogins);
        stats.put("totalEvents", totalEvents);
        stats.put("suspiciousActivity", suspiciousActivity);

        return stats;
    }

    @GetMapping("/events")
    public List<SecurityEvent> getRecentSecurityEvents() {
        return securityEventRepository
                .findTop100ByOrderByEventTimeDesc();
    }

}
