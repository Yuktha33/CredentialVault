
package com.Credential.Vault.dto;

import java.time.LocalDateTime;

public class CredentialResponse {

    private Long id;
    private String title;
    private String website;
    private String username;
    private String password;
    private String notes;
    private String category;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    public CredentialResponse() {
    }

    public CredentialResponse(
            Long id,
            String title,
            String website,
            String username,
            String password,
            String notes,
            String category,
            LocalDateTime createdAt,
            LocalDateTime updatedAt
    ) {
        this.id = id;
        this.title = title;
        this.website = website;
        this.username = username;
        this.password = password;
        this.notes = notes;
        this.category=category;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }

    public Long getId() {
        return id;
    }

    public String getTitle() {
        return title;
    }

    public String getWebsite() {
        return website;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getNotes() {
        return notes;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }
}
