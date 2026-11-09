
package com.Credential.Vault.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "security_events")
public class SecurityEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_email", length = 255)
    private String userEmail;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(nullable = false, length = 50)
    private String eventType;

    @Column(nullable = false, length = 30)
    private String status;

    @Column(length = 500)
    private String details;

    @Column(nullable = false)
    private LocalDateTime eventTime;

    public SecurityEvent() {
    }

    // Existing constructor - preserves old service calls
    public SecurityEvent(
            String userEmail,
            String eventType,
            String status,
            String details) {

        this(userEmail, null, eventType, status, details);
    }

    // New constructor with IP address
    public SecurityEvent(
            String userEmail,
            String ipAddress,
            String eventType,
            String status,
            String details) {

        this.userEmail = userEmail;
        this.ipAddress = ipAddress;
        this.eventType = eventType;
        this.status = status;
        this.details = details;
        this.eventTime = LocalDateTime.now();
    }

    @PrePersist
    protected void onCreate() {
        if (eventTime == null) {
            eventTime = LocalDateTime.now();
        }
    }

    public Long getId() {
        return id;
    }

    public String getUserEmail() {
        return userEmail;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public String getEventType() {
        return eventType;
    }

    public String getStatus() {
        return status;
    }

    public String getDetails() {
        return details;
    }

    public LocalDateTime getEventTime() {
        return eventTime;
    }
}
