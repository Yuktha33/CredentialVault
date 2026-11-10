
package com.Credential.Vault.controller;

import com.Credential.Vault.entity.User;
import com.Credential.Vault.repository.UserRepository;
import com.Credential.Vault.service.TwoFactorService;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/user/2fa")
@PreAuthorize("hasRole('USER')")
public class UserSecurityController {

    private final UserRepository userRepository;
    private final TwoFactorService twoFactorService;
    private final PasswordEncoder passwordEncoder;

    public UserSecurityController(
            UserRepository userRepository,
            TwoFactorService twoFactorService,
            PasswordEncoder passwordEncoder) {

        this.userRepository = userRepository;
        this.twoFactorService = twoFactorService;
        this.passwordEncoder = passwordEncoder;
    }

    // SEND 2FA SETUP OTP
    @PostMapping("/setup")
    public ResponseEntity<Map<String, String>> setupTwoFactor(
            Authentication authentication) {

        User user = getLoggedInUser(authentication);

        if (Boolean.TRUE.equals(user.getTwoFactorEnabled())) {
            return ResponseEntity.badRequest().body(
                    Map.of("message",
                            "Two-Factor Authentication is already enabled.")
            );
        }

        twoFactorService.generateAndSendSetupOtp(user);

        return ResponseEntity.ok(
                Map.of("message",
                        "Setup verification code sent to your registered email.")
        );
    }

    // VERIFY OTP AND ENABLE 2FA
    @PostMapping("/verify")
    public ResponseEntity<Map<String, String>> verifyTwoFactorSetup(
            @RequestBody Map<String, String> request,
            Authentication authentication) {

        User user = getLoggedInUser(authentication);

        String otp = request.get("otp");

        if (otp == null || !otp.matches("[0-9]{6}")) {
            return ResponseEntity.badRequest().body(
                    Map.of("message", "Enter a valid 6-digit OTP.")
            );
        }

        if (Boolean.TRUE.equals(user.getTwoFactorEnabled())) {
            return ResponseEntity.badRequest().body(
                    Map.of("message",
                            "Two-Factor Authentication is already enabled.")
            );
        }

        twoFactorService.verifySetupOtp(user, otp);

        user.setTwoFactorEnabled(true);
        userRepository.save(user);

        return ResponseEntity.ok(
                Map.of("message",
                        "Two-Factor Authentication enabled successfully.")
        );
    }

    // DISABLE 2FA
    @PostMapping("/disable")
    public ResponseEntity<Map<String, String>> disableTwoFactor(
            @RequestBody Map<String, String> request,
            Authentication authentication) {

        User user = getLoggedInUser(authentication);

        if (!Boolean.TRUE.equals(user.getTwoFactorEnabled())) {
            return ResponseEntity.badRequest().body(
                    Map.of("message",
                            "Two-Factor Authentication is already disabled.")
            );
        }

        String currentPassword = request.get("currentPassword");

        if (currentPassword == null || currentPassword.isBlank()
                || !passwordEncoder.matches(
                currentPassword, user.getPasswordHash())) {

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                    Map.of("message", "Incorrect current password.")
            );
        }

        user.setTwoFactorEnabled(false);
        userRepository.save(user);

        return ResponseEntity.ok(
                Map.of("message",
                        "Two-Factor Authentication disabled successfully.")
        );
    }

    // GET LOGGED-IN USER'S 2FA STATUS
    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getTwoFactorStatus(
            Authentication authentication) {

        User user = getLoggedInUser(authentication);

        return ResponseEntity.ok(
                Map.of(
                        "twoFactorEnabled",
                        Boolean.TRUE.equals(user.getTwoFactorEnabled())
                )
        );
    }

    private User getLoggedInUser(Authentication authentication) {

        String email = authentication.getName();

        return userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new IllegalArgumentException("User not found."));
    }
}
