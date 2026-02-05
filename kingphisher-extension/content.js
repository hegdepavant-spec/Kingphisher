// KingPhisher – Content Script (AUTO SCAN, SELF TRIGGER)

window.addEventListener("load", () => {
  scanWebsite();
});

function scanWebsite() {
  fetch("http://127.0.0.1:5000/predict", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: window.location.href })
  })
  .then(res => res.json())
  .then(data => {
    showResultCard(data.prediction, data.confidence);

    // store result for popup
    chrome.runtime.sendMessage({
      type: "SCAN_RESULT",
      data: {
        site: window.location.hostname,
        prediction: data.prediction,
        confidence: data.confidence
      }
    });
  })
  .catch(err => {
    console.error("Scan failed:", err);
  });
}

function showResultCard(prediction, confidence) {
  const old = document.getElementById("kingphisher-card");
  if (old) old.remove();

  let bg = "#2ecc71";
  let icon = "✔";
  let title = "Safe Website";

  if (prediction === "Phishing") {
    bg = "#e74c3c";
    icon = "⚠";
    title = "Phishing Detected";
  } else if (prediction === "Suspicious") {
    bg = "#f39c12";
    icon = "⚠";
    title = "Suspicious Website";
  }

  const card = document.createElement("div");
  card.id = "kingphisher-card";

  card.innerHTML = `
    <div style="display:flex;gap:12px;align-items:center;">
      <div style="
        width:36px;height:36px;border-radius:50%;
        background:rgba(255,255,255,0.25);
        display:flex;align-items:center;justify-content:center;
        font-size:18px;">${icon}</div>
      <div>
        <div style="font-weight:600;">KingPhisher</div>
        <div style="font-size:13px;">${title}</div>
        <div style="font-size:11px;">Confidence: ${confidence}%</div>
      </div>
    </div>
  `;

  card.style.cssText = `
    position:fixed;
    bottom:20px;
    left:20px;
    z-index:999999;
    padding:14px 18px;
    border-radius:14px;
    background:${bg};
    color:white;
    font-family:system-ui, sans-serif;
    box-shadow:0 12px 30px rgba(0,0,0,0.35);
  `;

  document.body.appendChild(card);
}
