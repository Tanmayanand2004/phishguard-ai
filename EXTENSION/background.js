const API_BASE = "http://localhost:8000/api/v1";

// Store scan results for each tab
const tabResults = {};

// Listen for tab URL changes
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "loading" && tab.url) {
    const url = tab.url;

    // Skip browser internal pages
    if (url.startsWith("chrome://") || 
        url.startsWith("chrome-extension://") ||
        url.startsWith("about:")) {
      return;
    }

    console.log(`PhishGuard: Scanning ${url}`);
    scanUrl(url, tabId);
  }
});

async function scanUrl(url, tabId) {
  try {
    // Call your PhishGuard API
    const response = await fetch(`${API_BASE}/scan/url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url })
    });

    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }

    const result = await response.json();

    // Store result for this tab
    tabResults[tabId] = {
      url: url,
      is_phishing: result.is_phishing,
      confidence: result.confidence,
      risk_percentage: result.risk_percentage,
      label: result.label,
      scan_time_ms: result.scan_time_ms,
      scanned_at: new Date().toISOString()
    };

    // Update extension icon based on result
    if (result.is_phishing) {
      // Red badge for phishing
      chrome.action.setBadgeText({ text: "!", tabId });
      chrome.action.setBadgeBackgroundColor({ color: "#FF0000", tabId });

      // Inject warning into the page
      chrome.tabs.sendMessage(tabId, {
        type: "PHISHING_DETECTED",
        data: result
      });

    } else {
      // Green badge for safe
      chrome.action.setBadgeText({ text: "✓", tabId });
      chrome.action.setBadgeBackgroundColor({ color: "#00AA00", tabId });
    }

  } catch (error) {
    console.error("PhishGuard scan error:", error);
    tabResults[tabId] = { error: error.message, url };
  }
}

// Expose tab results to popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "GET_RESULT") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tabId = tabs[0]?.id;
      sendResponse(tabResults[tabId] || null);
    });
    return true; // Keep message channel open for async response
  }
});

// Clean up when tab closes
chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabResults[tabId];
});