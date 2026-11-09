
// ========================================
// SECURE VAULT - BREACH DETECTION
// ========================================

const API_BASE_URL = "http://localhost:8080";

const scanBtn = document.getElementById("scanBreachesBtn");
const scanStatus = document.getElementById("scanStatus");

const passwordsChecked = document.getElementById("passwordsChecked");
const compromisedPasswords = document.getElementById("compromisedPasswords");
const safePasswords = document.getElementById("safePasswords");

const resultCount = document.getElementById("resultCount");
const breachResultsBody = document.getElementById("breachResultsBody");

const breachWarning = document.getElementById("breachWarning");
const breachWarningMessage = document.getElementById("breachWarningMessage");


// ========================================
// SCAN PASSWORDS
// ========================================

scanBtn.addEventListener("click", async () => {

    const token = localStorage.getItem("vaultToken");

    if (!token) {
        scanStatus.textContent = "Please login again.";
        scanStatus.style.color = "#dc2626";
        return;
    }

    scanBtn.disabled = true;
    scanBtn.textContent = "Scanning...";

    // Hide previous warning while a new scan is running
    breachWarning.hidden = true;

    scanStatus.textContent = "Checking your saved passwords...";
    scanStatus.style.color = "#3730a3";

    try {

        const response = await fetch(
            `${API_BASE_URL}/api/user/breach/scan`,
            {
                method: "POST",
                headers: {
                    "Authorization": `Bearer ${token}`
                }
            }
        );

        if (response.status === 401 || response.status === 403) {
            throw new Error(
                "Session expired or access denied. Please login again."
            );
        }

        if (!response.ok) {
            throw new Error(
                "Unable to scan passwords. Please try again."
            );
        }

        const results = await response.json();

        displayResults(results);

    } catch (error) {

        scanStatus.textContent = error.message;
        scanStatus.style.color = "#dc2626";

        breachWarning.hidden = true;

    } finally {

        scanBtn.disabled = false;
        scanBtn.textContent = "🔍 Scan My Saved Passwords";

    }

});


// ========================================
// DISPLAY SCAN RESULTS
// ========================================

function displayResults(results) {

    let compromised = 0;
    let safe = 0;

    passwordsChecked.textContent = results.length;

    breachResultsBody.innerHTML = "";

    results.forEach(result => {

        if (result.breached) {
            compromised++;
        } else {
            safe++;
        }

        const row = document.createElement("tr");

        // Website
        const websiteCell = document.createElement("td");

        websiteCell.textContent =
            result.website || result.title || "Unknown";

        // Scan status
        const statusCell = document.createElement("td");

        const statusBadge = document.createElement("span");

        statusBadge.className = result.breached
            ? "breach-danger"
            : "breach-safe";

        statusBadge.textContent = result.breached
            ? "Compromised"
            : "Safe";

        statusCell.appendChild(statusBadge);

        // Occurrences
        const occurrencesCell = document.createElement("td");

        occurrencesCell.textContent =
            Number(result.occurrences).toLocaleString();

        // Recommendation
        const recommendationCell = document.createElement("td");

        recommendationCell.textContent = result.breached
            ? "Change this password immediately."
            : "No exposure found in checked records.";

        row.appendChild(websiteCell);
        row.appendChild(statusCell);
        row.appendChild(occurrencesCell);
        row.appendChild(recommendationCell);

        breachResultsBody.appendChild(row);

    });


    // ========================================
    // UPDATE STATISTICS
    // ========================================

    compromisedPasswords.textContent = compromised;
    safePasswords.textContent = safe;

    resultCount.textContent =
        `${results.length} credentials scanned`;


    // ========================================
    // SECURITY WARNING
    // ========================================

    if (compromised > 0) {

        breachWarning.hidden = false;

        breachWarningMessage.textContent =
            `${compromised} of your saved passwords have appeared ` +
            `in known data breaches. Change these passwords immediately ` +
            `to protect your accounts.`;

    } else {

        breachWarning.hidden = true;

    }


    // ========================================
    // SCAN STATUS
    // ========================================

    if (results.length === 0) {

        scanStatus.textContent =
            "No saved credentials found. Add credentials before scanning.";

        scanStatus.style.color = "#3730a3";

        const emptyRow = document.createElement("tr");
        const emptyCell = document.createElement("td");

        emptyCell.colSpan = 4;
        emptyCell.style.textAlign = "center";
        emptyCell.textContent = "No credentials available to scan.";

        emptyRow.appendChild(emptyCell);
        breachResultsBody.appendChild(emptyRow);

    } else if (compromised > 0) {

        scanStatus.textContent =
            "Scan completed. Security issues were detected. Please review the warning.";

        scanStatus.style.color = "#dc2626";

    } else {

        scanStatus.textContent =
            "Scan completed successfully. No compromised passwords were found in the checked records.";

        scanStatus.style.color = "#166534";

    }

}
