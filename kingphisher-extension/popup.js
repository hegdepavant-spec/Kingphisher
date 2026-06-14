chrome.runtime.sendMessage({ type: "GET_STATUS" }, (data) => {
  const card = document.getElementById("statusCard");
  const historySummary = document.getElementById("historySummary");

  if (!data || data.prediction === "-") {
    card.className = "card unknown";
    card.innerHTML = "No website scanned yet";
    return;
  }

  const className =
    data.prediction === "Phishing"
      ? "phishing"
      : data.prediction === "Suspicious"
      ? "suspicious"
      : "safe";

  const threats = (data.reasons || [])
    .slice(0, 4)
    .map((reason) => `<li>${escapeHtml(reason)}</li>`)
    .join("");

  card.className = `card ${className}`;
  card.innerHTML = `
    <strong>${data.prediction}</strong>
    <div class="site">${escapeHtml(data.url || data.site || "")}</div>
    <div class="metric">Risk Score: ${data.risk_score ?? "n/a"}</div>
    <div class="metric">Confidence: ${data.confidence ?? 0}%</div>
    ${threats ? `<ul>${threats}</ul>` : ""}
  `;

  renderHistorySummary(data.lastHistoryScan, historySummary);
});

document.getElementById("historyScanButton").addEventListener("click", () => {
  const button = document.getElementById("historyScanButton");
  const historySummary = document.getElementById("historySummary");
  button.disabled = true;
  button.textContent = "Scanning history...";
  historySummary.textContent = "Collecting recent browser history and sending it to KingPhisher.";

  chrome.runtime.sendMessage(
    {
      type: "SCAN_BROWSER_HISTORY",
      options: { lookbackHours: 24, maxResults: 25 }
    },
    (response) => {
      button.disabled = false;
      button.textContent = "Scan browser history";

      if (!response?.ok) {
        historySummary.textContent = response?.error || "Browser history scan failed.";
        return;
      }

      renderHistorySummary(
        {
          scanned_at: new Date().toISOString(),
          total: response.result.total,
          batch_id: response.result.batch_id,
          items: response.result.items
        },
        historySummary
      );
    }
  );
});

function renderHistorySummary(scan, element) {
  if (!element) return;
  if (!scan) {
    element.textContent = "History scan not run yet.";
    return;
  }

  const phishing = (scan.items || []).filter((item) => item.status === "Phishing").length;
  const suspicious = (scan.items || []).filter((item) => item.status === "Suspicious").length;
  const safe = (scan.items || []).filter((item) => item.status === "Safe").length;
  element.innerHTML = `
    <strong>${scan.total || 0} history entries analyzed</strong>
    <div class="metric">Safe: ${safe} | Suspicious: ${suspicious} | Phishing: ${phishing}</div>
    <div class="metric">Batch: ${escapeHtml(scan.batch_id || "n/a")}</div>
  `;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
