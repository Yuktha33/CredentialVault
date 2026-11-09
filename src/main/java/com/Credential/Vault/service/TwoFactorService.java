package com.Credential.Vault.service;
import com.Credential.Vault.entity.TwoFactorOtp;
import com.Credential.Vault.entity.User;
import com.Credential.Vault.repository.TwoFactorOtpRepository;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Optional;

@Service
public class TwoFactorService {

    private final TwoFactorOtpRepository otpRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;

    private final SecureRandom secureRandom = new SecureRandom();

    public TwoFactorService(
            TwoFactorOtpRepository otpRepository,
            PasswordEncoder passwordEncoder,
            EmailService emailService) {

        this.otpRepository = otpRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
    }

    // GENERATE AND SEND LOGIN OTP
    @Transactional
    public void generateAndSendOtp(User user) {

        // Remove previous OTP
        otpRepository.deleteByUser(user);

        // Generate a six-digit OTP
        String otp = String.format(
                "%06d",
                secureRandom.nextInt(1000000)
        );

        // Hash OTP before storing
        String otpHash = passwordEncoder.encode(otp);

        // Set expiry to 5 minutes
        LocalDateTime expiryTime =
                LocalDateTime.now().plusMinutes(5);

        TwoFactorOtp otpRecord = new TwoFactorOtp(
                user,
                otpHash,
                expiryTime
        );

        otpRepository.save(otpRecord);

        // Send OTP to registered email
        emailService.sendTwoFactorOtp(
                user.getEmail(),
                otp
        );
    }

    // GENERATE AND SEND 2FA SETUP OTP
    @Transactional
    public void generateAndSendSetupOtp(User user) {

        // Delete previous setup OTP only
        otpRepository.deleteByUserAndPurpose(user, "SETUP");

        // Generate six-digit OTP
        String otp = String.format(
                "%06d",
                secureRandom.nextInt(1000000)
        );

        // Hash OTP before storing
        String otpHash = passwordEncoder.encode(otp);

        // OTP expires after 5 minutes
        LocalDateTime expiryTime =
                LocalDateTime.now().plusMinutes(5);

        // Save setup OTP
        TwoFactorOtp otpRecord = new TwoFactorOtp(
                user,
                otpHash,
                expiryTime,
                "SETUP"
        );

        otpRepository.save(otpRecord);

        // Send OTP to registered email
        emailService.sendTwoFactorOtp(
                user.getEmail(),
                otp
        );
    }

    // VERIFY 2FA SETUP OTP
    @Transactional(noRollbackFor = IllegalArgumentException.class)
    public boolean verifySetupOtp(User user, String enteredOtp) {

        Optional<TwoFactorOtp> optionalOtp =
                otpRepository.findTopByUserAndPurposeOrderByCreatedAtDesc(
                        user,
                        "SETUP"
                );

        if (optionalOtp.isEmpty()) {
            throw new IllegalArgumentException(
                    "Setup OTP not found. Please request a new OTP."
            );
        }

        TwoFactorOtp otpRecord = optionalOtp.get();

        // Check expiry
        if (LocalDateTime.now().isAfter(otpRecord.getExpiresAt())) {
            otpRepository.delete(otpRecord);

            throw new IllegalArgumentException(
                    "Setup OTP has expired. Please request a new OTP."
            );
        }

        // Check maximum attempts
        if (otpRecord.getAttempts() >= 5) {
            otpRepository.delete(otpRecord);

            throw new IllegalArgumentException(
                    "Maximum OTP attempts exceeded. Please request a new OTP."
            );
        }

        // Verify entered OTP
        if (!passwordEncoder.matches(
                enteredOtp,
                otpRecord.getOtpHash())) {

            otpRecord.setAttempts(otpRecord.getAttempts() + 1);
            otpRepository.save(otpRecord);

            throw new IllegalArgumentException(
                    "Invalid OTP. Please try again."
            );
        }

        // Delete OTP after successful verification
        otpRepository.delete(otpRecord);

        return true;
    }

// VERIFY LOGIN OTP
@Transactional(noRollbackFor = IllegalArgumentException.class)
    public boolean verifyOtp(User user, String enteredOtp) {

        Optional<TwoFactorOtp> optionalOtp =
                otpRepository.findTopByUserOrderByCreatedAtDesc(user);

        if (optionalOtp.isEmpty()) {
            throw new IllegalArgumentException(
                    "OTP not found. Please request a new OTP."
            );
        }

        TwoFactorOtp otpRecord = optionalOtp.get();

        // Check expiry
        if (LocalDateTime.now().isAfter(otpRecord.getExpiresAt())) {
            otpRepository.delete(otpRecord);

            throw new IllegalArgumentException(
                    "OTP has expired. Please request a new OTP."
            );
        }

        // Check maximum attempts
        if (otpRecord.getAttempts() >= 5) {
            otpRepository.delete(otpRecord);

            throw new IllegalArgumentException(
                    "Maximum OTP attempts exceeded. Please login again."
            );
        }

        // Verify OTP
        if (!passwordEncoder.matches(
                enteredOtp,
                otpRecord.getOtpHash())) {

            otpRecord.setAttempts(
                    otpRecord.getAttempts() + 1
            );

            otpRepository.save(otpRecord);

            throw new IllegalArgumentException(
                    "Invalid OTP. Please try again."
            );
        }

        // OTP successfully verified
        otpRepository.delete(otpRecord);

        return true;
    }

}
