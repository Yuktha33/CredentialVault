// ========================================
// SECURE VAULT - USER DASHBOARD
// ========================================

const API_BASE_URL = "http://localhost:8080";

// ========================================
// 1. AUTHENTICATION
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
// 2. API REQUEST
// ========================================

async function dashboardApiRequest(url) {

    const token = getToken();

    const response = await fetch(API_BASE_URL + url, {
        method: "GET",
        headers: {
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json"
        }
    });

    if (!response.ok) {
        throw new Error("Unable to load dashboard information.");
    }

    return response.json();
}

// ========================================
// 3. DASHBOARD STATISTICS
// ========================================

async function loadDashboardStatistics() {

    const totalElement =
        document.getElementById("totalCredentials");

    const sharedElement =
        document.getElementById("sharedCredentials");

    const recentElement =
        document.getElementById("recentCredentials");

    try {

        const [credentials, sharedCredentials] =
            await Promise.all([
                dashboardApiRequest("/api/user/credentials"),
                dashboardApiRequest("/api/shares/received")
            ]);

        const total = Array.isArray(credentials)
            ? credentials.length
            : 0;

        const shared = Array.isArray(sharedCredentials)
            ? sharedCredentials.length
            : 0;

        const sevenDaysAgo = new Date();
        sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

        const recent = Array.isArray(credentials)
            ? credentials.filter(item => {
                if (!item.createdAt) return false;

                return new Date(item.createdAt) >= sevenDaysAgo;
            }).length
            : 0;

        if (totalElement) {
            totalElement.textContent = total;
        }

        if (sharedElement) {
            sharedElement.textContent = shared;
        }

        if (recentElement) {
            recentElement.textContent = recent;
        }

    } catch (error) {

        console.error("Dashboard error:", error);

        if (totalElement) totalElement.textContent = "-";
        if (sharedElement) sharedElement.textContent = "-";
        if (recentElement) recentElement.textContent = "-";
    }
}

// ========================================
// 4. LOGOUT
// ========================================

const logoutBtn = document.getElementById("logoutBtn");

if (logoutBtn) {

    logoutBtn.addEventListener("click", () => {

        const confirmed =
            confirm("Are you sure you want to logout?");

        if (!confirmed) return;

        localStorage.removeItem("vaultToken");
        localStorage.removeItem("vaultRole");
        localStorage.removeItem("vaultName");
        localStorage.removeItem("vaultEmail");

        window.location.href = "login.html";
    });
}

// ========================================
// 5. INITIALIZE DASHBOARD
// ========================================

document.addEventListener("DOMContentLoaded", () => {

    if (!checkAuthentication()) return;

    loadDashboardStatistics();

});

console.log("SecureVault dashboard initialized.");