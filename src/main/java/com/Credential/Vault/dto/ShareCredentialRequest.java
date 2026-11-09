
package com.Credential.Vault.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public class ShareCredentialRequest {

    @NotBlank(message = "Recipient email is required")
    @Email(message = "Enter a valid email address")
    private String recipientEmail;

    @NotBlank(message = "Permission is required")
    @Pattern(
            regexp = "VIEW|EDIT",
            message = "Permission must be VIEW or EDIT"
    )
    private String permission;

    public String getRecipientEmail() {
        return recipientEmail;
    }

    public void setRecipientEmail(String recipientEmail) {
        this.recipientEmail = recipientEmail;
    }

    public String getPermission() {
        return permission;
    }

    public void setPermission(String permission) {
        this.permission = permission;
    }
}
