// Listen for phishing detection message from background
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "PHISHING_DETECTED") {
    showPhishingWarning(message.data);
  }
});

function showPhishingWarning(result) {
  // Don't show duplicate warnings
  if (document.getElementById("phishguard-warning")) return;

  const confidence = Math.round(result.risk_percentage);

  const banner = document.createElement("div");
  banner.id = "phishguard-warning";
  banner.innerHTML = `
    <div style="
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      z-index: 999999;
      background: linear-gradient(135deg, #ff0000, #cc0000);
      color: white;
      padding: 16px 24px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      font-size: 15px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      box-shadow: 0 4px 20px rgba(0,0,0,0.4);
    ">
      <div style="display: flex; align-items: center; gap: 12px;">
        <span style="font-size: 24px;">⚠️</span>
        <div>
          <div style="font-weight: 700; font-size: 16px;">
            PhishGuard AI: Phishing Website Detected
          </div>
          <div style="opacity: 0.9; font-size: 13px; margin-top: 2px;">
            Risk score: ${confidence}% — This page may be attempting to steal your credentials
          </div>
        </div>
      </div>
      <button onclick="document.getElementById('phishguard-warning').remove()" style="
        background: rgba(255,255,255,0.2);
        border: 1px solid rgba(255,255,255,0.4);
        color: white;
        padding: 6px 14px;
        border-radius: 6px;
        cursor: pointer;
        font-size: 13px;
        white-space: nowrap;
      ">Dismiss</button>
    </div>
  `;

  document.body.insertBefore(banner, document.body.firstChild);

  // Auto-dismiss after 10 seconds
  setTimeout(() => {
    const el = document.getElementById("phishguard-warning");
    if (el) el.remove();
  }, 10000);
}