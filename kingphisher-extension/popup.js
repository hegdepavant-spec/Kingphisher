chrome.runtime.sendMessage({ type: "GET_STATUS" }, (data) => {
  const card = document.getElementById("statusCard");

  if (!data || data.prediction === "—") {
    card.style.background = "#7f8c8d";
    card.innerHTML = "No website scanned yet";
    return;
  }

  let bg = "#2ecc71";
  if (data.prediction === "Phishing") bg = "#e74c3c";
  if (data.prediction === "Suspicious") bg = "#f39c12";

  card.style.background = bg;
  card.innerHTML = `
    <b>${data.prediction}</b><br>
    ${data.site}<br>
    Confidence: ${data.confidence}%
  `;
});
