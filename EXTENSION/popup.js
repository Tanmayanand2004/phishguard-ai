document.addEventListener("DOMContentLoaded", () => {
  // Ask background for current tab's result
  chrome.runtime.sendMessage({ type: "GET_RESULT" }, (result) => {
    if (!result) {
      showScanning();
      return;
    }
    if (result.error) {
      showError(result.error);
      return;
    }
    showResult(result);
  });
});

function showScanning() {
  document.getElementById("status-icon").textContent = "⏳";
  document.getElementById("status-label").textContent = "Scanning...";
  document.getElementById("status-url").textContent = "Analyzing this page";
}

function showError(error) {
  const card = document.getElementById("status-card");
  card.className = "status-card status-scanning";
  document.getElementById("status-icon").textContent = "⚠️";
  document.getElementById("status-label").textContent = "API Offline";
  document.getElementById("status-url").textContent = "Start your PhishGuard server";
}

function showResult(result) {
  const card = document.getElementById("status-card");
  const isPhishing = result.is_phishing;

  // Update card style
  card.className = `status-card ${isPhishing ? "status-phishing" : "status-safe"}`;

  // Update icon and label
  document.getElementById("status-icon").textContent = isPhishing ? "🚨" : "✅";
  document.getElementById("status-label").textContent = isPhishing ? "PHISHING DETECTED" : "SAFE";

  // Show URL
  const url = result.url || "";
  document.getElementById("status-url").textContent =
    url.length > 50 ? url.substring(0, 50) + "..." : url;

  // Risk bar
  const riskPct = Math.round(result.risk_percentage || 0);
  document.getElementById("risk-percent").textContent = `${riskPct}%`;
  document.getElementById("risk-fill").style.width = `${riskPct}%`;
  document.getElementById("risk-fill").style.background =
    isPhishing ? "#ff3232" : "#00c864";

  // Stats
  const confidence = Math.round((result.confidence || 0) * 100);
  document.getElementById("confidence-val").textContent = `${confidence}%`;
  document.getElementById("scan-time-val").textContent =
    result.scan_time_ms ? `${Math.round(result.scan_time_ms)}ms` : "—";
}