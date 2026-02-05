let lastScan = {
  site: "Not scanned yet",
  prediction: "—",
  confidence: 0
};

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "complete") {
    chrome.tabs.sendMessage(tabId, { action: "AUTO_SCAN" });
  }
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  if (msg.type === "SCAN_RESULT") {
    lastScan = msg.data;
  }

  if (msg.type === "GET_STATUS") {
    sendResponse(lastScan);
    return true;
  }
});
