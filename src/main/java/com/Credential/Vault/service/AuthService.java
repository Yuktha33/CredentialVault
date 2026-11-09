 package com.Credential.Vault.service;
import com.Credential.Vault.dto.LoginRequest;
import com.Credential.Vault.dto.RegisterRequest;
import com.Credential.Vault.dto.ChangePasswordRequest;
import com.Credential.Vault.dto.TwoFactorVerifyRequest;
import com.Credential.Vault.entity.Role;
import com.Credential.Vault.entity.User;
import com.Credential.Vault.repository.UserRepository;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Map;

@Service
public class AuthService {

    private static final int FAILED_LOGIN_THRESHOLD = 5;
    private static final int FAILED_LOGIN_WINDOW_MINUTES = 10;

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final SecurityMonitoringService securityMonitoringService;
    private final EmailService emailService;
    private final TwoFactorService twoFactorService;

    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtService jwtService,
            SecurityMonitoringService securityMonitoringService,
            EmailService emailService,
            TwoFactorService twoFactorService) {

        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.securityMonitoringService = securityMonitoringService;
        this.emailService = emailService;
        this.twoFactorService=twoFactorService;
    }

    // ========================================
    // REGISTER A NEW USER
    // ========================================

    @Transactional
    public Map<String, Object> register(RegisterRequest request) {

        String name = request.getName().trim();
        String email = request.getEmail().trim().toLowerCase();

        if (userRepository.existsByEmail(email)) {
            throw new IllegalArgumentException(
                    "Email is already registered"
            );
        }

        User user = new User();

        user.setName(name);
        user.setEmail(email);

        user.setPasswordHash(
                passwordEncoder.encode(request.getPassword())
        );

        user.setRole(Role.USER);

        User savedUser = userRepository.save(user);

        return Map.of(
                "message", "Registration successful",
                "id", savedUser.getId(),
                "name", savedUser.getName(),
                "email", savedUser.getEmail(),
                "role", savedUser.getRole().name()
        );
    }

    // ========================================
    // LOGIN WITH SECURITY MONITORING
    // ========================================


// LOGIN WITH TWO-FACTOR AUTHENTICATION
    @Transactional
    public Map<String, Object> login(
            LoginRequest request,
            String ipAddress) {

        String email = request.getEmail().trim().toLowerCase();

        User user = userRepository.findByEmail(email).orElse(null);

        // User does not exist
        if (user == null) {
            recordFailedLogin(
                    email,
                    ipAddress,
                    "Login failed: invalid credentials",
                    null
            );

            throw new IllegalArgumentException(
                    "Invalid email or password"
            );
        }

        // Check account status and password
        if (!Boolean.TRUE.equals(user.getActive())
                || !passwordEncoder.matches(
                request.getPassword(),
                user.getPasswordHash())) {

            recordFailedLogin(
                    email,
                    ipAddress,
                    Boolean.TRUE.equals(user.getActive())
                            ? "Login failed: invalid credentials"
                            : "Login failed: account inactive",
                    user
            );

            throw new IllegalArgumentException(
                    "Invalid email or password"
            );
        }

        // CHECK WHETHER 2FA IS ENABLED
        if (Boolean.TRUE.equals(user.getTwoFactorEnabled())) {

            // Generate and send OTP
            twoFactorService.generateAndSendOtp(user);

            return Map.of(
                    "message", "Verification code sent to your registered email",
                    "twoFactorRequired", true,
                    "email", maskEmail(user.getEmail())
            );
        }

        // NORMAL LOGIN WHEN 2FA IS DISABLED
        securityMonitoringService.recordEvent(
                email,
                ipAddress,
                "LOGIN",
                "SUCCESS",
                "User logged in successfully"
        );

        String token = jwtService.generateToken(user);

        return Map.of(
                "message", "Login successful",
                "token", token,
                "tokenType", "Bearer",
                "expiresIn", 3600,
                "id", user.getId(),
                "name", user.getName(),
                "email", user.getEmail(),
                "role", user.getRole().name()
        );
    }


    // VERIFY TWO-FACTOR LOGIN OTP
    public Map<String, Object> verifyTwoFactorLogin(
            TwoFactorVerifyRequest request,
            String ipAddress) {

        String email = request.getEmail().trim().toLowerCase();

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Invalid verification request"
                ));

        if (!Boolean.TRUE.equals(user.getActive())
                || !Boolean.TRUE.equals(user.getTwoFactorEnabled())) {

            throw new IllegalArgumentException(
                    "Invalid verification request"
            );
        }

        // Verify OTP
        twoFactorService.verifyOtp(user, request.getOtp());

        // Record successful login only after OTP verification
        securityMonitoringService.recordEvent(
                email,
                ipAddress,
                "LOGIN",
                "SUCCESS",
                "User logged in successfully with two-factor authentication"
        );

        // Generate JWT after successful OTP verification
        String token = jwtService.generateToken(user);

        return Map.of(
                "message", "Login successful",
                "token", token,
                "tokenType", "Bearer",
                "expiresIn", 3600,
                "id", user.getId(),
                "name", user.getName(),
                "email", user.getEmail(),
                "role", user.getRole().name()
        );
    }

    // MASK EMAIL ADDRESS
    private String maskEmail(String email) {

        String[] parts = email.split("@");

        String username = parts[0];
        String domain = parts[1];

        if (username.length() <= 2) {
            return username.charAt(0) + "***@" + domain;
        }

        return username.substring(0, 2)
                + "***@"
                + domain;
    }


    // ========================================
    // FAILED LOGIN DETECTION
    // ========================================

    private void recordFailedLogin(
            String email,
            String ipAddress,
            String details,
            User user) {

        // Save failed login with email and IP
        securityMonitoringService.recordEvent(
                email,
                ipAddress,
                "LOGIN",
                "FAILED",
                details
        );

        LocalDateTime cutoff = LocalDateTime.now()
                .minusMinutes(FAILED_LOGIN_WINDOW_MINUTES);

        boolean emailDetected = false;
        boolean ipDetected = false;

        long emailAttempts =
                securityMonitoringService.countRecentFailedLogins(
                        email,
                        cutoff
                );

        // ========================================
        // 1. EMAIL-BASED DETECTION
        // ========================================

        if (emailAttempts == FAILED_LOGIN_THRESHOLD) {

            emailDetected = true;

            securityMonitoringService.recordEvent(
                    email,
                    ipAddress,
                    "SUSPICIOUS_LOGIN",
                    "DETECTED",
                    "Suspicious activity: "
                            + emailAttempts
                            + " failed login attempts for this email within "
                            + FAILED_LOGIN_WINDOW_MINUTES
                            + " minutes"
            );
        }

        // ========================================
        // 2. IP-BASED DETECTION
        // ========================================

        long ipAttempts = 0;

        if (ipAddress != null && !ipAddress.isBlank()) {

            ipAttempts =
                    securityMonitoringService.countRecentFailedLoginsByIp(
                            ipAddress,
                            cutoff
                    );

            if (ipAttempts == FAILED_LOGIN_THRESHOLD) {

                ipDetected = true;

                securityMonitoringService.recordEvent(
                        email,
                        ipAddress,
                        "SUSPICIOUS_LOGIN",
                        "DETECTED",
                        "Suspicious activity: "
                                + ipAttempts
                                + " failed login attempts from IP address "
                                + ipAddress
                                + " within "
                                + FAILED_LOGIN_WINDOW_MINUTES
                                + " minutes"
                );
            }
        }

        // ========================================
        // 3. SEND EMAIL NOTIFICATION
        // ========================================

        if ((emailDetected || ipDetected) && user != null) {

            String detectionType;

            if (emailDetected && ipDetected) {

                detectionType =
                        "Email-based and IP-based detection";

            } else if (emailDetected) {

                detectionType = "Email-based detection";

            } else {

                detectionType = "IP-based detection";
            }

            int detectedAttempts =
                    (int) Math.max(emailAttempts, ipAttempts);

            try {

                emailService.sendSuspiciousActivityAlert(
                        user.getEmail(),
                        ipAddress,
                        detectionType,
                        detectedAttempts,
                        LocalDateTime.now()
                );

            } catch (Exception exception) {

                System.err.println(
                        "Failed to send suspicious activity email: "
                                + exception.getMessage()
                );
            }
        }
    }

    // ========================================
    // CHANGE PASSWORD
    // ========================================

    @Transactional
    public String changePassword(
            String email,
            ChangePasswordRequest request) {

        User user = userRepository.findByEmail(
                email.trim().toLowerCase()
        ).orElseThrow(() ->
                new IllegalArgumentException("User not found")
        );

        if (!passwordEncoder.matches(
                request.getCurrentPassword(),
                user.getPasswordHash())) {

            throw new IllegalArgumentException(
                    "Current password is incorrect"
            );
        }

        if (!request.getNewPassword().equals(
                request.getConfirmPassword())) {

            throw new IllegalArgumentException(
                    "New password and confirm password do not match"
            );
        }

        if (passwordEncoder.matches(
                request.getNewPassword(),
                user.getPasswordHash())) {

            throw new IllegalArgumentException(
                    "New password must be different from current password"
            );
        }

        user.setPasswordHash(
                passwordEncoder.encode(request.getNewPassword())
        );

        userRepository.save(user);

        securityMonitoringService.recordEvent(
                email,
                "PASSWORD_CHANGE",
                "SUCCESS",
                "User changed password successfully"
        );

        return "Password changed successfully";
    }
}
