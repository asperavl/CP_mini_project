const API_BASE = "http://localhost:5000";

document.addEventListener("DOMContentLoaded", async () => {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const url = tab.url || "";
    document.getElementById("currentUrl").textContent = url || "No URL detected";
    loadHistory();
    if (url && !url.startsWith("chrome://") && !url.startsWith("about:") && !url.startsWith("chrome-extension://")
      && !url.startsWith("http://localhost") && !url.startsWith("https://localhost")
      && !url.startsWith("http://127.0.0.1") && !url.startsWith("https://127.0.0.1")) {
      autoScan(tab.id, url);
    } else {
      showError("Cannot scan browser internal pages.");
    }
  } catch (err) {
    document.getElementById("currentUrl").textContent = "Could not read tab URL";
  }
  document.getElementById("scanBtn").addEventListener("click", async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    autoScan(tab.id, tab.url, true);
  });
});

async function autoScan(tabId, url, force = false) {
  let host = "";
  try {
    host = new URL(url).hostname;
  } catch (err) {
    showError("Invalid URL format. Cannot scan.");
    return;
  }
  const key = `popup_scan_${tabId}_${encodeURIComponent(host)}`;
  if (!force) {
    const stored = await chrome.storage.session.get(key);
    if (stored[key]) {
      renderResult(stored[key]);
      return;
    }
  }

  showScanning();
  const btn = document.getElementById("scanBtn");
  btn.disabled = true;
  btn.textContent = "Scanning…";

  try {
    const res = await fetch(`${API_BASE}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, fetch_html: true })
    });

    let data;
    try {
      data = await res.json();
    } catch (_) {
      data = {};
    }

    if (!res.ok) {
      throw new Error(data.error || `Server error ${res.status}`);
    }

    chrome.storage.session.set({ [key]: data });
    renderResult(data);

    if (data.is_phishing) {
      const BLOCKED_PAGE = chrome.runtime.getURL("blocked.html");
      const blockedUrl = `${BLOCKED_PAGE}?url=${encodeURIComponent(data.url)}&risk=${data.risk_score}&conf=${data.confidence}&original=${encodeURIComponent(url)}`;
      setTimeout(() => {
        chrome.tabs.update(tabId, { url: blockedUrl });
      }, 800);
    }

    saveToLocalHistory(data);
    loadHistory();
  } catch (err) {
    if (err.message.includes("Failed to fetch") || err.message.includes("NetworkError")) {
      showError("Scan failed: Cannot connect to backend. Is the PhishGuard server running?");
    } else {
      showError(`Scan failed: ${err.message}`);
    }
  } finally {
    btn.disabled = false;
    btn.textContent = "🔄 Re-Scan";
  }
}

function showScanning() {
  document.getElementById("resultBox").classList.remove("visible");
  document.getElementById("errorMsg").classList.remove("visible");
  document.getElementById("scanningBox").classList.add("visible");
}

function renderResult(data) {
  document.getElementById("scanningBox").classList.remove("visible");
  document.getElementById("errorMsg").classList.remove("visible");

  const resultBox = document.getElementById("resultBox");
  const resultHeader = document.getElementById("resultHeader");
  const riskVal = document.getElementById("riskVal");
  const confVal = document.getElementById("confVal");
  const meterFill = document.getElementById("meterFill");
  const isPhish = data.is_phishing;

  resultHeader.textContent = isPhish ? "⚠  PHISHING DETECTED" : "✔  LEGITIMATE WEBSITE";
  resultHeader.className = "result-header " + (isPhish ? "phishing" : "safe");
  riskVal.textContent = `${(+data.risk_score).toFixed(1)}%`;
  riskVal.style.color = isPhish ? "var(--danger)" : "var(--safe)";
  confVal.textContent = `${(+data.confidence).toFixed(1)}%`;
  meterFill.style.width = "0%";
  setTimeout(() => { meterFill.style.width = `${data.risk_score}%`; }, 50);
  resultBox.classList.add("visible");
}

function showError(msg) {
  document.getElementById("scanningBox").classList.remove("visible");
  document.getElementById("resultBox").classList.remove("visible");
  const errorBox = document.getElementById("errorMsg");
  errorBox.textContent = msg;
  errorBox.classList.add("visible");
}

function saveToLocalHistory(data) {}

function loadHistory() {
  const list = document.getElementById("historyList");
  list.innerHTML = `<div style="color:var(--muted);font-size:11px;">Loading…</div>`;
  fetch(`${API_BASE}/api/history`)
    .then(r => r.json())
    .then(rows => {
      if (!rows.length) {
        list.innerHTML = `<div style="color:var(--muted);font-size:11px;">No scans yet.</div>`;
        return;
      }
      list.innerHTML = rows.slice(0, 5).map(item => `
        <div class="history-item">
          <span class="h-url" title="${item.url}">${item.url}</span>
          <span class="h-badge ${item.label === 'PHISHING' ? 'ph' : 'ok'}">${item.label}</span>
        </div>
      `).join("");
    })
    .catch(() => {
      list.innerHTML = `<div style="color:var(--muted);font-size:11px;">Could not load history.</div>`;
    });
}
