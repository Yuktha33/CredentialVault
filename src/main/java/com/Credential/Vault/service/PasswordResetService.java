
package com.Credential.Vault.service;

import com.Credential.Vault.dto.ForgotPasswordRequest;
import com.Credential.Vault.dto.ResetPasswordRequest;
import com.Credential.Vault.entity.PasswordResetToken;
import com.Credential.Vault.entity.User;
import com.Credential.Vault.repository.PasswordResetTokenRepository;
import com.Credential.Vault.repository.UserRepository;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Optional;

@Service
public class PasswordResetService {

    private final UserRepository userRepository;
    private final PasswordResetTokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;

    private final SecureRandom secureRandom = new SecureRandom();

    public PasswordResetService(
            UserRepository userRepository,
            PasswordResetTokenRepository tokenRepository,
            PasswordEncoder passwordEncoder,
            EmailService emailService) {

        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
    }

    // STEP 1: Generate and send OTP
    @Transactional
    public String forgotPassword(ForgotPasswordRequest request) {

        String email = request.getEmail().trim().toLowerCase();

        User user = userRepository.findByEmail(email).orElse(null);

        if (user == null) {
            return "If the email is registered, a verification code has been sent.";
        }

        // Delete previous OTP records immediately.
        tokenRepository.deleteByUser(user);

        // Generate a six-digit OTP.
        String otp = String.format(
                "%06d",
                secureRandom.nextInt(1_000_000)
        );

        // Store only the BCrypt hash.
        PasswordResetToken token = new PasswordResetToken();

        token.setUser(user);
        token.setTokenHash(passwordEncoder.encode(otp));
        token.setExpiryDate(LocalDateTime.now().plusMinutes(10));
        token.setUsed(false);
        token.setFailedAttempts(0);

        PasswordResetToken savedToken =
                tokenRepository.saveAndFlush(token);

        System.out.println(
                "Password reset OTP record created. ID: "
                        + savedToken.getId()
        );

        // Send the same OTP that was hashed.
        emailService.sendPasswordResetCode(email, otp);

        return "If the email is registered, a verification code has been sent.";
    }

    // STEP 2: Verify OTP and reset password
    @Transactional(noRollbackFor = IllegalArgumentException.class)
    public String resetPassword(ResetPasswordRequest request) {

        String email = request.getEmail().trim().toLowerCase();

        String enteredOtp = request.getVerificationCode().trim();

        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new IllegalArgumentException("Passwords do not match.");
        }

        User user = userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new IllegalArgumentException(
                                "Invalid or expired verification code."
                        )
                );

        PasswordResetToken token = tokenRepository
                .findTopByUserOrderByCreatedAtDesc(user)
                .orElseThrow(() ->
                        new IllegalArgumentException(
                                "Invalid or expired verification code."
                        )
                );

        // Check whether OTP has already been used.
        if (token.isUsed()) {
            throw new IllegalArgumentException(
                    "Invalid or expired verification code."
            );
        }

        // Check OTP expiry.
        if (!LocalDateTime.now().isBefore(token.getExpiryDate())) {

            token.setUsed(true);
            tokenRepository.save(token);

            throw new IllegalArgumentException(
                    "Verification code has expired. Request a new code."
            );
        }

        // Check maximum attempts.
        if (token.getFailedAttempts() >= 5) {

            token.setUsed(true);
            tokenRepository.save(token);

            throw new IllegalArgumentException(
                    "Too many attempts. Request a new code."
            );
        }

        // Compare entered OTP with stored BCrypt hash.
        boolean validOtp = passwordEncoder.matches(
                enteredOtp,
                token.getTokenHash()
        );

        if (!validOtp) {

            token.setFailedAttempts(
                    token.getFailedAttempts() + 1
            );

            if (token.getFailedAttempts() >= 5) {

                token.setUsed(true);

                tokenRepository.save(token);

                throw new IllegalArgumentException(
                        "Too many attempts. Request a new code."
                );
            }

            tokenRepository.save(token);

            throw new IllegalArgumentException(
                    "Incorrect verification code."
            );
        }

        // OTP is valid. Update password.
        user.setPasswordHash(
                passwordEncoder.encode(request.getNewPassword())
        );

        userRepository.save(user);

        // Mark OTP as used.
        token.setUsed(true);

        tokenRepository.save(token);

        return "Password reset successfully.";
    }
}
