const API_BASE = "http://127.0.0.1:5000";

let lastScan = {
  site: "Not scanned yet",
  url: "",
  prediction: "-",
  risk_score: 0,
  confidence: 0,
  reasons: [],
  details: [],
  scanned_at: null
};

const verdictColors = {
  Safe: "green",
  Suspicious: "yellow",
  Phishing: "red"
};

async function scanUrl(url) {
  const response = await fetch(`${API_BASE}/api/ensemble`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, use_html: true })
  });

  const data = await response.json();
  if (!response.ok) {
    throw new Error(data?.reasons?.[0] || "URL scan failed");
  }

  lastScan = {
    site: new URL(url).hostname,
    url,
    prediction: data.prediction || data.verdict || "Suspicious",
    risk_score: data.risk_score ?? 0.5,
    confidence: data.confidence ?? 0,
    reasons: data.reasons || [],
    details: data.details || [],
    color: verdictColors[data.prediction] || "yellow",
    scanned_at: new Date().toISOString()
  };

  chrome.storage.local.set({ lastScan });
  return lastScan;
}

async function postBrowserHistory(items) {
  console.info("[KingPhisher] Browser history scan posting records:", items.length);
  const response = await fetch(`${API_BASE}/api/browser-history`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ items, limit: items.length, use_html: false })
  });

  const data = await response.json();
  if (!response.ok) {
    throw new Error(data?.reasons?.[0] || "Browser history scan failed");
  }

  chrome.storage.local.set({
    lastHistoryScan: {
      scanned_at: new Date().toISOString(),
      total: data.total || 0,
      batch_id: data.batch_id,
      items: data.items || []
    }
  });
  console.info("[KingPhisher] Browser history scan complete:", data.total || 0);
  return data;
}

function scanBrowserHistory(options = {}) {
  const lookbackHours = Number(options.lookbackHours || 24);
  const maxResults = Number(options.maxResults || 25);
  const startTime = Date.now() - lookbackHours * 60 * 60 * 1000;

  return new Promise((resolve, reject) => {
    if (!chrome.history?.search) {
      reject(new Error("Chrome history permission is unavailable. Reload the extension after granting history permission."));
      return;
    }

    chrome.history.search(
      {
        text: "",
        startTime,
        maxResults
      },
      async (items) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }

        const records = (items || [])
          .filter((item) => item.url?.startsWith("http"))
          .map((item) => ({
            url: item.url,
            title: item.title || "",
            lastVisitTime: item.lastVisitTime,
            visitCount: item.visitCount || 0
          }));

        try {
          resolve(await postBrowserHistory(records));
        } catch (error) {
          reject(error);
        }
      }
    );
  });
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url?.startsWith("http")) {
    chrome.tabs.sendMessage(tabId, { action: "AUTO_SCAN", url: tab.url }).catch(() => {});
  }
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "SCAN_URL") {
    scanUrl(msg.url)
      .then((result) => sendResponse({ ok: true, result }))
      .catch((error) => sendResponse({ ok: false, error: error.message }));
    return true;
  }

  if (msg.type === "SCAN_RESULT") {
    lastScan = { ...lastScan, ...msg.data };
    chrome.storage.local.set({ lastScan });
  }

  if (msg.type === "SCAN_BROWSER_HISTORY") {
    scanBrowserHistory(msg.options || {})
      .then((result) => sendResponse({ ok: true, result }))
      .catch((error) => sendResponse({ ok: false, error: error.message }));
    return true;
  }

  if (msg.type === "GET_STATUS") {
    chrome.storage.local.get(["lastScan", "lastHistoryScan"], (stored) => {
      sendResponse({
        ...(stored.lastScan || lastScan),
        lastHistoryScan: stored.lastHistoryScan || null
      });
    });
    return true;
  }
});
