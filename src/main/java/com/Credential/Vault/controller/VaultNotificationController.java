
package com.Credential.Vault.controller;

import com.Credential.Vault.entity.VaultNotification;
import com.Credential.Vault.service.VaultNotificationService;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;

@RestController
@RequestMapping("/api")
public class VaultNotificationController {

    private final VaultNotificationService notificationService;

    public VaultNotificationController(
            VaultNotificationService notificationService) {
        this.notificationService = notificationService;
    }

    // ADMIN: Send a breach notification to a user
    @PostMapping("/admin/notifications/breach")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<NotificationResponse> notifyUser(
            @RequestBody NotifyRequest request) {

        VaultNotification notification =
                notificationService.notifyUser(
                        request.userId(),
                        request.credentialId(),
                        request.scanId()
                );

        return ResponseEntity.ok(toResponse(notification));
    }

    // ADMIN: View complete notification history
    @GetMapping("/admin/notifications/history")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<AdminNotificationResponse>>
    getAdminNotificationHistory() {

        List<AdminNotificationResponse> history =
                notificationService.getAllNotificationsForAdmin()
                        .stream()
                        .map(this::toAdminResponse)
                        .toList();

        return ResponseEntity.ok(history);
    }

    // USER: View their notifications
    @GetMapping("/user/notifications")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER', 'USER')")
    public ResponseEntity<List<NotificationResponse>> getNotifications(
            Authentication authentication) {

        List<NotificationResponse> notifications =
                notificationService
                        .getUserNotifications(authentication.getName())
                        .stream()
                        .map(this::toResponse)
                        .toList();

        return ResponseEntity.ok(notifications);
    }

    // USER: Check unread notification count
    @GetMapping("/user/notifications/unread-count")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER', 'USER')")
    public ResponseEntity<Long> getUnreadCount(
            Authentication authentication) {

        return ResponseEntity.ok(
                notificationService.getUnreadCount(
                        authentication.getName()
                )
        );
    }

    // USER: Mark notification as read
    @PatchMapping("/user/notifications/{id}/read")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER', 'USER')")
    public ResponseEntity<String> markAsRead(
            @PathVariable Long id,
            Authentication authentication) {

        notificationService.markAsRead(
                id,
                authentication.getName()
        );

        return ResponseEntity.ok("Notification marked as read");
    }

    // Convert notification to user response
    private NotificationResponse toResponse(
            VaultNotification notification) {

        return new NotificationResponse(
                notification.getId(),
                notification.getCredential().getId(),
                notification.getCredential().getTitle(),
                notification.getTitle(),
                notification.getMessage(),
                notification.getType(),
                notification.isRead(),
                notification.getCreatedAt()
        );
    }

    // Convert notification to admin history response
    private AdminNotificationResponse toAdminResponse(
            VaultNotification notification) {

        return new AdminNotificationResponse(
                notification.getId(),
                notification.getUser().getId(),
                notification.getUser().getName(),
                notification.getUser().getEmail(),
                notification.getCredential().getId(),
                notification.getCredential().getTitle(),
                notification.getTitle(),
                notification.getMessage(),
                notification.getType(),
                notification.isRead(),
                notification.getCreatedAt()
        );
    }

    public record NotifyRequest(
            Long userId,
            Long credentialId,
            String scanId
    ) {}

    public record NotificationResponse(
            Long id,
            Long credentialId,
            String credentialTitle,
            String title,
            String message,
            String type,
            boolean read,
            LocalDateTime createdAt
    ) {}

    public record AdminNotificationResponse(
            Long id,
            Long userId,
            String userName,
            String userEmail,
            Long credentialId,
            String credentialTitle,
            String title,
            String message,
            String type,
            boolean read,
            LocalDateTime createdAt
    ) {}
}
