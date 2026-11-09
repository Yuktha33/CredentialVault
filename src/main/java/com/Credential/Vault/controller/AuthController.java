
package com.Credential.Vault.controller;

import com.Credential.Vault.dto.*;

import com.Credential.Vault.service.AuthService;
import com.Credential.Vault.service.PasswordResetService;

import jakarta.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

import org.springframework.security.core.Authentication;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final PasswordResetService passwordResetService;

    public AuthController(
            AuthService authService,
            PasswordResetService passwordResetService) {

        this.authService = authService;
        this.passwordResetService = passwordResetService;
    }

    // REGISTER
    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(
            @Valid @RequestBody RegisterRequest request) {

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(authService.register(request));
    }

    // LOGIN
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(
            @Valid @RequestBody LoginRequest request,
            jakarta.servlet.http.HttpServletRequest httpRequest) {

        String ipAddress = httpRequest.getRemoteAddr();

        return ResponseEntity.ok(
                authService.login(request, ipAddress)
        );
    }

// VERIFY TWO-FACTOR LOGIN OTP
    @PostMapping("/verify-2fa")
    public ResponseEntity<Map<String, Object>> verifyTwoFactorLogin(
            @Valid @RequestBody TwoFactorVerifyRequest request,
            jakarta.servlet.http.HttpServletRequest httpRequest) {

        String ipAddress = httpRequest.getRemoteAddr();

        return ResponseEntity.ok(
                authService.verifyTwoFactorLogin(
                        request,
                        ipAddress
                )
        );
    }


    // FORGOT PASSWORD - SEND OTP

    @PostMapping("/forgot-password")
    public ResponseEntity<Map<String, String>> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request) {

        String message = passwordResetService.forgotPassword(request);

        return ResponseEntity.ok(Map.of("message", message));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<Map<String, String>> resetPassword(
            @Valid @RequestBody ResetPasswordRequest request) {

        String message = passwordResetService.resetPassword(request);

        return ResponseEntity.ok(Map.of("message", message));
    }
    // CHANGE PASSWORD
    @PostMapping("/change-password")
    public ResponseEntity<Map<String, String>> changePassword(
            @Valid @RequestBody ChangePasswordRequest request,
            Authentication authentication) {

        String email = authentication.getName();

        String message = authService.changePassword(email, request);

        return ResponseEntity.ok(
                Map.of("message", message)
        );
    }
}
