
package com.Credential.Vault.controller;

import com.Credential.Vault.dto.CreateStaffRequest;
import com.Credential.Vault.entity.Role;
import com.Credential.Vault.entity.User;
import com.Credential.Vault.repository.PasswordResetTokenRepository;
import com.Credential.Vault.repository.UserRepository;

import jakarta.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import org.springframework.security.core.Authentication;
import com.Credential.Vault.service.TwoFactorService;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TwoFactorService twoFactorService;

    public AdminController(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            PasswordResetTokenRepository passwordResetTokenRepository,
            TwoFactorService twoFactorService) {

        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.passwordResetTokenRepository=passwordResetTokenRepository;
        this.twoFactorService=twoFactorService;
    }

    // Get all users
    @GetMapping("/users")
    public ResponseEntity<List<Map<String, Object>>> getAllUsers() {

        List<Map<String, Object>> users = userRepository.findAll()
                .stream()
                .map(user -> {
                    Map<String, Object> result = new LinkedHashMap<>();

                    result.put("id", user.getId());
                    result.put("name", user.getName());
                    result.put("email", user.getEmail());
                    result.put("role", user.getRole().name());
                    result.put("active", user.getActive());
                    result.put("createdAt", user.getCreatedAt());

                    return result;
                })
                .toList();

        return ResponseEntity.ok(users);
    }

    // Create Admin or Manager
    @PostMapping("/create-staff")
    public ResponseEntity<Map<String, String>> createStaff(
            @Valid @RequestBody CreateStaffRequest request) {

        String email = request.getEmail().trim().toLowerCase();

        if (request.getRole() != Role.ADMIN &&
                request.getRole() != Role.MANAGER) {

            return ResponseEntity.badRequest().body(
                    Map.of("message",
                            "Only ADMIN and MANAGER accounts can be created here.")
            );
        }

        if (userRepository.existsByEmail(email)) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(
                    Map.of("message", "Email is already registered.")
            );
        }

        User user = new User();

        user.setName(request.getName().trim());
        user.setEmail(email);
        user.setPasswordHash(
                passwordEncoder.encode(request.getPassword())
        );
        user.setRole(request.getRole());
        user.setActive(true);

        userRepository.save(user);

        return ResponseEntity.status(HttpStatus.CREATED).body(
                Map.of("message",
                        request.getRole() + " account created successfully.")
        );
    }


    // GET LOGGED-IN ADMIN PROFILE
    @GetMapping("/profile")
    public ResponseEntity<Map<String, Object>> getAdminProfile(
            Authentication authentication) {

        String email = authentication.getName();

        User admin = userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new IllegalArgumentException("Admin not found"));

        Map<String, Object> profile = new LinkedHashMap<>();

        profile.put("id", admin.getId());
        profile.put("name", admin.getName());
        profile.put("email", admin.getEmail());
        profile.put("role", admin.getRole().name());
        profile.put("twoFactorEnabled", admin.getTwoFactorEnabled());

        return ResponseEntity.ok(profile);
    }


    // Delete user
    @DeleteMapping("/users/{id}")
    @Transactional
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {

        User user = userRepository.findById(id)
                .orElseThrow(() ->
                        new IllegalArgumentException("User not found"));

        // Delete password reset OTP records first
        passwordResetTokenRepository.deleteByUser(user);

        // Delete the user
        userRepository.delete(user);

        return ResponseEntity.ok(
                Map.of("message", "User deleted successfully")
        );
    }
    // UPDATE LOGGED-IN ADMIN PROFILE
    @PutMapping("/profile")
    public ResponseEntity<Map<String, String>> updateAdminProfile(
            @RequestBody Map<String, String> request,
            Authentication authentication) {

        String email = authentication.getName();

        User admin = userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new IllegalArgumentException("Admin not found"));

        String name = request.get("name");

        if (name == null || name.trim().length() < 2
                || name.trim().length() > 50) {

            return ResponseEntity.badRequest().body(
                    Map.of("message",
                            "Name must contain 2 to 50 characters.")
            );
        }

        admin.setName(name.trim());

        userRepository.save(admin);

        return ResponseEntity.ok(
                Map.of("message", "Profile updated successfully.")
        );
    }
    // SEND 2FA SETUP OTP
    @PostMapping("/2fa/setup")
    public ResponseEntity<Map<String, String>> setupTwoFactor(
            Authentication authentication) {

        String email = authentication.getName();

        User admin = userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new IllegalArgumentException("Admin not found"));

        if (Boolean.TRUE.equals(admin.getTwoFactorEnabled())) {
            return ResponseEntity.badRequest().body(
                    Map.of("message", "Two-Factor Authentication is already enabled.")
            );
        }

        twoFactorService.generateAndSendSetupOtp(admin);

        return ResponseEntity.ok(
                Map.of("message", "Setup verification code sent to your registered email.")
        );
    }
    // VERIFY SETUP OTP AND ENABLE 2FA
    @PostMapping("/2fa/verify")
    public ResponseEntity<Map<String, String>> verifyTwoFactorSetup(
            @RequestBody Map<String, String> request,
            Authentication authentication) {

        String email = authentication.getName();

        User admin = userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new IllegalArgumentException("Admin not found"));

        String otp = request.get("otp");

        if (otp == null || !otp.matches("[0-9]{6}")) {
            return ResponseEntity.badRequest().body(
                    Map.of("message", "Enter a valid 6-digit OTP.")
            );
        }

        if (Boolean.TRUE.equals(admin.getTwoFactorEnabled())) {
            return ResponseEntity.badRequest().body(
                    Map.of("message", "Two-Factor Authentication is already enabled.")
            );
        }

        // Verify setup OTP
        twoFactorService.verifySetupOtp(admin, otp);

        // Enable 2FA only after successful verification
        admin.setTwoFactorEnabled(true);

        userRepository.save(admin);

        return ResponseEntity.ok(
                Map.of("message", "Two-Factor Authentication enabled successfully.")
        );
    }

    // DISABLE TWO-FACTOR AUTHENTICATION
    @PostMapping("/2fa/disable")
    public ResponseEntity<Map<String, String>> disableTwoFactor(
            @RequestBody Map<String, String> request,
            Authentication authentication) {

        String email = authentication.getName();

        User admin = userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new IllegalArgumentException("Admin not found"));

        // Check whether 2FA is enabled
        if (!Boolean.TRUE.equals(admin.getTwoFactorEnabled())) {
            return ResponseEntity.badRequest().body(
                    Map.of("message", "Two-Factor Authentication is already disabled.")
            );
        }

        String currentPassword = request.get("currentPassword");

        // Validate current password
        if (currentPassword == null || currentPassword.isBlank()
                || !passwordEncoder.matches(
                currentPassword, admin.getPasswordHash())) {

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                    Map.of("message", "Incorrect current password.")
            );
        }

        // Disable 2FA
        admin.setTwoFactorEnabled(false);
        userRepository.save(admin);

        return ResponseEntity.ok(
                Map.of("message", "Two-Factor Authentication disabled successfully.")
        );
    }

}
