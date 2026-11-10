
package com.Credential.Vault.service;

import com.Credential.Vault.entity.Credential;
import com.Credential.Vault.entity.User;
import com.Credential.Vault.entity.VaultNotification;
import com.Credential.Vault.repository.CredentialRepository;
import com.Credential.Vault.repository.UserRepository;
import com.Credential.Vault.repository.VaultNotificationRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class VaultNotificationService {

    private final VaultNotificationRepository notificationRepository;
    private final UserRepository userRepository;
    private final CredentialRepository credentialRepository;

    public VaultNotificationService(
            VaultNotificationRepository notificationRepository,
            UserRepository userRepository,
            CredentialRepository credentialRepository) {

        this.notificationRepository = notificationRepository;
        this.userRepository = userRepository;
        this.credentialRepository = credentialRepository;
    }

    @Transactional
    public VaultNotification notifyUser(
            Long userId,
            Long credentialId,
            String scanId) {

        User user = userRepository.findById(userId)
                .orElseThrow(() ->
                        new IllegalArgumentException("User not found"));

        Credential credential = credentialRepository.findById(credentialId)
                .orElseThrow(() ->
                        new IllegalArgumentException("Credential not found"));

        // Verify that the credential belongs to the selected user
        if (credential.getOwner() == null ||
                !credential.getOwner().getId().equals(userId)) {

            throw new IllegalArgumentException(
                    "Credential does not belong to this user");
        }

        // Prevent duplicate notifications for the same scan
        if (notificationRepository.existsByUserAndCredentialIdAndScanId(
                user, credentialId, scanId)) {

            throw new IllegalStateException(
                    "Notification already sent for this scan");
        }

        VaultNotification notification = new VaultNotification();

        notification.setUser(user);
        notification.setCredential(credential);
        notification.setScanId(scanId);
        notification.setTitle("Compromised Password Detected");

        notification.setMessage(
                "The password saved for \"" +
                        credential.getTitle() +
                        "\" has appeared in known data breaches. " +
                        "Please change it immediately."
        );

        notification.setType("SECURITY_BREACH");
        notification.setRead(false);

        VaultNotification saved =
                notificationRepository.save(notification);

        return notificationRepository.findByIdAndUser(
                        saved.getId(), user)
                .orElseThrow(() ->
                        new RuntimeException(
                                "Notification not found after saving"));
    }

    // Get notifications belonging to a particular user
    @Transactional(readOnly = true)
    public List<VaultNotification> getUserNotifications(String email) {

        User user = userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new IllegalArgumentException("User not found"));

        return notificationRepository
                .findByUserOrderByCreatedAtDesc(user);
    }

    // Get unread notification count
    @Transactional(readOnly = true)
    public long getUnreadCount(String email) {

        User user = userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new IllegalArgumentException("User not found"));

        return notificationRepository.countByUserAndReadFalse(user);
    }

    // Mark a user's notification as read
    @Transactional
    public void markAsRead(Long notificationId, String email) {

        User user = userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new IllegalArgumentException("User not found"));

        VaultNotification notification =
                notificationRepository
                        .findByIdAndUser(notificationId, user)
                        .orElseThrow(() ->
                                new IllegalArgumentException(
                                        "Notification not found"));

        notification.setRead(true);

        notificationRepository.save(notification);
    }

    // ADMIN: Get complete notification history
    @Transactional(readOnly = true)
    public List<VaultNotification> getAllNotificationsForAdmin() {

        return notificationRepository
                .findAllByOrderByCreatedAtDesc();
    }
}
