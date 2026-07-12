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

function dataUrlToBlob(dataUrl) {
  const [header, base64] = dataUrl.split(",");
  const mime = header.match(/data:(.*?);base64/)?.[1] || "image/png";
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return new Blob([bytes], { type: mime });
}

function captureVisibleScreenshot(windowId) {
  return new Promise((resolve) => {
    chrome.tabs.captureVisibleTab(
      windowId,
      { format: "png" },
      (dataUrl) => {
        if (chrome.runtime.lastError || !dataUrl) {
          console.warn("[KingPhisher] Screenshot capture failed:", chrome.runtime.lastError?.message);
          resolve(null);
          return;
        }
        resolve(dataUrl);
      }
    );
  });
}

async function scanUrl(url, tabWindowId = chrome.windows.WINDOW_ID_CURRENT) {
  const screenshot = await captureVisibleScreenshot(tabWindowId);
  const formData = new FormData();
  formData.append("url", url);
  formData.append("source", "extension");
  if (screenshot) {
    formData.append("image", dataUrlToBlob(screenshot), "page-screenshot.png");
  }

  const response = await fetch(`${API_BASE}/api/ensemble`, {
    method: "POST",
    body: formData
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
    scanUrl(msg.url, sender.tab?.windowId)
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
