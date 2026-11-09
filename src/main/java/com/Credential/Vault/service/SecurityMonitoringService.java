
package com.Credential.Vault.service;

import com.Credential.Vault.entity.SecurityEvent;
import com.Credential.Vault.repository.SecurityEventRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
public class SecurityMonitoringService {

    private final SecurityEventRepository securityEventRepository;

    public SecurityMonitoringService(
            SecurityEventRepository securityEventRepository) {

        this.securityEventRepository = securityEventRepository;
    }

    // Existing method - preserves current functionality
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordEvent(
            String email,
            String eventType,
            String status,
            String details) {

        recordEvent(email, null, eventType, status, details);
    }

    // New method - records event with IP address
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordEvent(
            String email,
            String ipAddress,
            String eventType,
            String status,
            String details) {

        SecurityEvent event = new SecurityEvent(
                email,
                ipAddress,
                eventType,
                status,
                details
        );

        securityEventRepository.save(event);
    }

    // Existing email-based count
    public long countRecentFailedLogins(
            String email,
            LocalDateTime cutoff) {

        return securityEventRepository
                .countByUserEmailAndEventTypeAndStatusAndEventTimeAfter(
                        email,
                        "LOGIN",
                        "FAILED",
                        cutoff
                );
    }

    // New IP-based count
    public long countRecentFailedLoginsByIp(
            String ipAddress,
            LocalDateTime cutoff) {

        return securityEventRepository
                .countByIpAddressAndEventTypeAndStatusAndEventTimeAfter(
                        ipAddress,
                        "LOGIN",
                        "FAILED",
                        cutoff
                );
    }
}
