
package com.Credential.Vault.dto;

public class UserDashboardResponse {

    private String userName;
    private String userEmail;
    private String role;
    private Boolean active;

    private long totalCredentials;
    private long sharedCredentials;
    private long recentCredentials;

    public UserDashboardResponse(
            String userName,
            String userEmail,
            String role,
            Boolean active,
            long totalCredentials,
            long sharedCredentials,
            long recentCredentials) {

        this.userName = userName;
        this.userEmail = userEmail;
        this.role = role;
        this.active = active;
        this.totalCredentials = totalCredentials;
        this.sharedCredentials = sharedCredentials;
        this.recentCredentials = recentCredentials;
    }

    public String getUserName() {
        return userName;
    }

    public String getUserEmail() {
        return userEmail;
    }

    public String getRole() {
        return role;
    }

    public Boolean getActive() {
        return active;
    }

    public long getTotalCredentials() {
        return totalCredentials;
    }

    public long getSharedCredentials() {
        return sharedCredentials;
    }

    public long getRecentCredentials() {
        return recentCredentials;
    }
}
