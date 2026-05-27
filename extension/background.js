const API_BASE = "http://localhost:5000";
const BLOCKED_PAGE = chrome.runtime.getURL("blocked.html");
const SCANNING_PAGE = chrome.runtime.getURL("scanning.html");

const scannedTabs = {};

function shouldSkip(url) {
  if (!url) return true;
  if (url.startsWith("chrome://") || url.startsWith("chrome-error://")) return true;
  if (url.startsWith("about:") || url.startsWith("chrome-extension://")) return true;
  if (url.startsWith("http://localhost") || url.startsWith("https://localhost")) return true;
  if (url.startsWith("http://127.0.0.1") || url.startsWith("https://127.0.0.1")) return true;
  return false;
}

async function scanTab(tabId, url) {
  if (shouldSkip(url)) return;

  let host;
  try { host = new URL(url).hostname; } catch (_) { return; }

  const scanKey = `${tabId}:${host}`;
  if (scannedTabs[scanKey]) return;
  scannedTabs[scanKey] = true;
  setTimeout(() => { delete scannedTabs[scanKey]; }, 30000);

  chrome.action.setBadgeText({ tabId, text: "…" });
  chrome.action.setBadgeBackgroundColor({ tabId, color: "#6b7a99" });

  try {
    const res = await fetch(`${API_BASE}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, fetch_html: true })
    });

    if (!res.ok) { delete scannedTabs[scanKey]; return; }
    const data = await res.json();
    if (data.error) { delete scannedTabs[scanKey]; return; }

    const popupKey = `popup_scan_${tabId}_${encodeURIComponent(host)}`;
    chrome.storage.session.set({ [popupKey]: data });

    const isHighRisk = data.is_phishing && data.risk_score >= 60;

    if (isHighRisk) {
      chrome.action.setBadgeText({ tabId, text: "⚠" });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#ef4444" });
      const blockedUrl = `${BLOCKED_PAGE}?url=${encodeURIComponent(data.url)}&risk=${data.risk_score}&conf=${data.confidence}&original=${encodeURIComponent(url)}`;
      chrome.tabs.update(tabId, { url: blockedUrl });
    } else if (data.is_phishing) {
      chrome.action.setBadgeText({ tabId, text: "⚠" });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#f59e0b" });
    } else {
      chrome.action.setBadgeText({ tabId, text: "✓" });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#22c55e" });
    }
  } catch (_) {
    delete scannedTabs[scanKey];
    chrome.action.setBadgeText({ tabId, text: "?" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#6b7a99" });
  }
}

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  scanTab(details.tabId, details.url);
});

chrome.webNavigation.onErrorOccurred.addListener((details) => {
  if (details.frameId !== 0) return;
  if (shouldSkip(details.url)) return;
  scanTab(details.tabId, details.url);
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete" || !tab.url) return;
  scanTab(tabId, tab.url);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  for (const key of Object.keys(scannedTabs)) {
    if (key.startsWith(`${tabId}:`)) delete scannedTabs[key];
  }
});
