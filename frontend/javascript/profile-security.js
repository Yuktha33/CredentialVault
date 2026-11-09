
// ========================================
// SECURE VAULT - PROFILE & SECURITY
// ========================================

const API_BASE_URL = "http://localhost:8080";

// ========================================
// AUTHENTICATION
// ========================================

function getToken() {
    return localStorage.getItem("vaultToken");
}

function checkAuthentication() {
    if (!getToken()) {
        alert("Please login to continue.");
        window.location.href = "login.html";
        return false;
    }

    return true;
}

// ========================================
// LOAD PROFILE INFORMATION
// ========================================

function loadProfileInformation() {
    const name = document.getElementById("profileName");
    const email = document.getElementById("profileEmail");
    const role = document.getElementById("profileRole");

    if (name) {
        name.textContent =
            localStorage.getItem("vaultName") || "-";
    }

    if (email) {
        email.textContent =
            localStorage.getItem("vaultEmail") || "-";
    }

    if (role) {
        role.textContent =
            localStorage.getItem("vaultRole") || "USER";
    }
}

// ========================================
// CHANGE PASSWORD
// ========================================

function setupChangePassword() {

    const form = document.getElementById("changePasswordForm");

    if (!form) return;

    form.addEventListener("submit", async event => {

        event.preventDefault();

        const currentPassword =
            document.getElementById("currentPassword").value;

        const newPassword =
            document.getElementById("newPassword").value;

        const confirmPassword =
            document.getElementById("confirmNewPassword").value;

        const message =
            document.getElementById("changePasswordMessage");

        const button =
            document.getElementById("changePasswordBtn");

        if (newPassword.length < 8) {
            message.textContent =
                "New password must contain at least 8 characters.";
            message.className = "error";
            return;
        }

        if (newPassword !== confirmPassword) {
            message.textContent =
                "New passwords do not match.";
            message.className = "error";
            return;
        }

        if (currentPassword === newPassword) {
            message.textContent =
                "New password must be different from the current password.";
            message.className = "error";
            return;
        }

        try {

            button.disabled = true;
            button.textContent = "Updating...";

            const response = await fetch(
                API_BASE_URL + "/api/auth/change-password",
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Authorization": "Bearer " + getToken()
                    },
                    body: JSON.stringify({
                        currentPassword: currentPassword,
                        newPassword: newPassword,
                        confirmPassword: confirmPassword
                    })
                }
            );

            const data = await response.json().catch(() => null);

            if (!response.ok) {
                throw new Error(
                    data?.message || "Password update failed."
                );
            }

            message.textContent =
                data?.message || "Password changed successfully!";

            message.className = "success";

            form.reset();

        } catch (error) {

            message.textContent = error.message;
            message.className = "error";

        } finally {

            button.disabled = false;
            button.textContent = "Change Password";

        }
    });
}

// ========================================
// LOGOUT
// ========================================

function setupLogout() {

    const logoutBtn = document.getElementById("logoutBtn");

    if (!logoutBtn) return;

    logoutBtn.addEventListener("click", () => {

        const confirmed = confirm(
            "Are you sure you want to logout?"
        );

        if (!confirmed) return;

        localStorage.removeItem("vaultToken");
        localStorage.removeItem("vaultRole");
        localStorage.removeItem("vaultName");
        localStorage.removeItem("vaultEmail");

        window.location.href = "login.html";
    });
}

// ========================================
// INITIALIZE
// ========================================

document.addEventListener("DOMContentLoaded", () => {

    if (!checkAuthentication()) return;

    loadProfileInformation();
    setupChangePassword();
    setupLogout();

});

console.log("SecureVault profile and security initialized.");
