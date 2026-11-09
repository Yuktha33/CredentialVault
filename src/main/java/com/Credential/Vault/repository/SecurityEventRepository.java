
package com.Credential.Vault.repository;

import com.Credential.Vault.entity.SecurityEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface SecurityEventRepository
        extends JpaRepository<SecurityEvent, Long> {

    List<SecurityEvent> findTop100ByOrderByEventTimeDesc();

    long countByEventTypeAndStatus(
            String eventType,
            String status
    );

    // Existing email-based detection
    long countByUserEmailAndEventTypeAndStatusAndEventTimeAfter(
            String userEmail,
            String eventType,
            String status,
            LocalDateTime after
    );

    // New IP-based detection
    long countByIpAddressAndEventTypeAndStatusAndEventTimeAfter(
            String ipAddress,
            String eventType,
            String status,
            LocalDateTime after
    );
}
