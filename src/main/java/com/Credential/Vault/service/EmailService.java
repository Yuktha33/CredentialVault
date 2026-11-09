package com.Credential.Vault.service;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Service
public class EmailService {

    private final JavaMailSender mailSender;

    public EmailService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    // Password reset OTP email
    public void sendPasswordResetCode(String email, String code) {

        SimpleMailMessage message = new SimpleMailMessage();

        message.setTo(email);
        message.setSubject(
                "Credential Vault - Password Verification Code"
        );

        message.setText(
                "Hello,\n\n"
                        + "We received a request to reset your Credential Vault password.\n\n"
                        + "Your password reset verification code is:\n\n"
                        + code + "\n\n"
                        + "This code expires in 10 minutes.\n"
                        + "Do not share this code with anyone.\n\n"
                        + "If you did not request this, please ignore this email.\n\n"
                        + "Regards,\n"
                        + "Credential Vault Team"
        );

        mailSender.send(message);
    }


    // Two-Factor Authentication OTP email
    public void sendTwoFactorOtp(String email, String code) {

        SimpleMailMessage message = new SimpleMailMessage();

        message.setTo(email);

        message.setSubject(
                "Credential Vault - Login Verification Code"
        );

        message.setText(
                "Hello,\n\n"
                        + "A login attempt was made to your Credential Vault account.\n\n"
                        + "Your Two-Factor Authentication verification code is:\n\n"
                        + code + "\n\n"
                        + "This code expires in 5 minutes.\n"
                        + "You can use this code only once.\n\n"
                        + "Do not share this code with anyone.\n\n"
                        + "If you did not attempt to log in, please secure your account immediately.\n\n"
                        + "Regards,\n"
                        + "Credential Vault Security Team"
        );

        mailSender.send(message);
    }


    // Suspicious login activity notification
    public void sendSuspiciousActivityAlert(
            String email,
            String ipAddress,
            String detectionType,
            int failedAttempts,
            LocalDateTime detectionTime) {

        SimpleMailMessage message = new SimpleMailMessage();

        String formattedTime = detectionTime.format(
                DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss")
        );

        String safeIpAddress =
                (ipAddress == null || ipAddress.isBlank())
                        ? "Unavailable"
                        : ipAddress;

        message.setTo(email);

        message.setSubject(
                "Credential Vault - Suspicious Login Activity Detected"
        );

        message.setText(
                "Hello,\n\n"
                        + "Credential Vault has detected suspicious login activity "
                        + "associated with your account.\n\n"
                        + "Security Alert Details:\n"
                        + "Detection Type: " + detectionType + "\n"
                        + "IP Address: " + safeIpAddress + "\n"
                        + "Failed Login Attempts: " + failedAttempts + "\n"
                        + "Detection Time: " + formattedTime + "\n\n"
                        + "Our security system detected repeated unsuccessful login attempts.\n\n"
                        + "If this activity was not performed by you, we recommend "
                        + "changing your password immediately and reviewing your account security.\n\n"
                        + "Never share your password or verification codes with anyone.\n\n"
                        + "Regards,\n"
                        + "Credential Vault Security Team"
        );

        mailSender.send(message);
    }
}
