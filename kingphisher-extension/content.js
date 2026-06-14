let kingphisherScan = null;
let kingphisherProceedAnyway = false;

window.addEventListener("load", () => {
  runRealtimeProtection();
  attachCredentialProtection();
});

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.action === "AUTO_SCAN") {
    runRealtimeProtection();
  }
});

function runRealtimeProtection() {
  if (!window.location.href.startsWith("http")) return;

  chrome.runtime.sendMessage(
    { type: "SCAN_URL", url: window.location.href },
    (response) => {
      if (!response?.ok) {
        showStatusCard({
          prediction: "Suspicious",
          confidence: 50,
          risk_score: 0.5,
          reasons: [response?.error || "Backend scan unavailable"]
        });
        return;
      }

      kingphisherScan = response.result;
      showStatusCard(response.result);

      if (["Suspicious", "Phishing"].includes(response.result.prediction)) {
        showSecurityWarning(response.result, false);
      }
    }
  );
}

function statusTheme(prediction) {
  if (prediction === "Phishing") {
    return {
      background: "#dc2626",
      border: "#991b1b",
      title: "Phishing Detected",
      icon: "!"
    };
  }
  if (prediction === "Suspicious") {
    return {
      background: "#d97706",
      border: "#92400e",
      title: "Suspicious Website",
      icon: "!"
    };
  }
  return {
    background: "#16a34a",
    border: "#166534",
    title: "Safe Website",
    icon: "✓"
  };
}

function showStatusCard(result) {
  const old = document.getElementById("kingphisher-card");
  if (old) old.remove();

  const theme = statusTheme(result.prediction);
  const card = document.createElement("div");
  card.id = "kingphisher-card";
  card.innerHTML = `
    <div style="display:flex;gap:12px;align-items:center;">
      <div style="
        width:34px;height:34px;border-radius:50%;
        background:rgba(255,255,255,0.22);
        display:flex;align-items:center;justify-content:center;
        font-weight:800;font-size:18px;">${theme.icon}</div>
      <div>
        <div style="font-weight:700;">KingPhisher</div>
        <div style="font-size:13px;">${theme.title}</div>
        <div style="font-size:11px;">Risk: ${result.risk_score} | Confidence: ${result.confidence}%</div>
      </div>
    </div>
  `;
  card.style.cssText = `
    position:fixed;
    bottom:20px;
    left:20px;
    z-index:2147483647;
    padding:14px 18px;
    border-radius:10px;
    background:${theme.background};
    border:1px solid ${theme.border};
    color:white;
    font-family:system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    box-shadow:0 14px 34px rgba(0,0,0,0.35);
  `;
  document.documentElement.appendChild(card);
}

function showSecurityWarning(result, isCredentialSubmission) {
  if (kingphisherProceedAnyway) return;

  const old = document.getElementById("kingphisher-warning");
  if (old) old.remove();

  const threats = result.reasons?.length
    ? result.reasons
    : ["High-risk phishing indicators were detected"];
  const actionText = isCredentialSubmission
    ? "Do not submit passwords, email addresses, or login details on this page."
    : "Go back unless you fully trust this website and expected to visit it.";

  const overlay = document.createElement("div");
  overlay.id = "kingphisher-warning";
  overlay.innerHTML = `
    <div class="kp-warning-panel">
      <div class="kp-warning-kicker">Security Warning</div>
      <h1>Potential phishing page blocked</h1>
      <div class="kp-score">Risk Score: <strong>${result.risk_score}</strong></div>
      <section>
        <h2>Detected Threats</h2>
        <ul>${threats.slice(0, 6).map((reason) => `<li>${escapeHtml(reason)}</li>`).join("")}</ul>
      </section>
      <section>
        <h2>Recommended Actions</h2>
        <ul>
          <li>${actionText}</li>
          <li>Close the page if you did not intentionally open it.</li>
          <li>Use the official website or app instead of links from messages or QR codes.</li>
        </ul>
      </section>
      <div class="kp-actions">
        <button id="kp-go-back" type="button">Go Back</button>
        <button id="kp-proceed" type="button">Proceed Anyway</button>
      </div>
    </div>
  `;

  const style = document.createElement("style");
  style.textContent = `
    #kingphisher-warning {
      position: fixed;
      inset: 0;
      z-index: 2147483647;
      display: grid;
      place-items: center;
      background: rgba(7, 10, 18, 0.94);
      color: #f8fafc;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    #kingphisher-warning .kp-warning-panel {
      width: min(720px, calc(100vw - 32px));
      max-height: calc(100vh - 32px);
      overflow: auto;
      background: #111827;
      border: 1px solid #ef4444;
      border-radius: 8px;
      padding: 28px;
      box-shadow: 0 28px 80px rgba(0, 0, 0, 0.55);
    }
    #kingphisher-warning .kp-warning-kicker {
      color: #fca5a5;
      font-size: 13px;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0;
    }
    #kingphisher-warning h1 {
      margin: 8px 0 14px;
      font-size: 30px;
      line-height: 1.15;
    }
    #kingphisher-warning h2 {
      margin: 20px 0 8px;
      font-size: 15px;
      color: #e5e7eb;
    }
    #kingphisher-warning .kp-score {
      display: inline-block;
      background: #7f1d1d;
      border: 1px solid #ef4444;
      border-radius: 6px;
      padding: 8px 12px;
    }
    #kingphisher-warning ul {
      margin: 0;
      padding-left: 20px;
      color: #cbd5e1;
    }
    #kingphisher-warning li {
      margin: 6px 0;
    }
    #kingphisher-warning .kp-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      margin-top: 24px;
    }
    #kingphisher-warning button {
      border: 0;
      border-radius: 6px;
      padding: 11px 16px;
      color: white;
      font-weight: 800;
      cursor: pointer;
    }
    #kp-go-back {
      background: #dc2626;
    }
    #kp-proceed {
      background: #374151;
    }
  `;
  overlay.appendChild(style);
  document.documentElement.appendChild(overlay);

  document.getElementById("kp-go-back").addEventListener("click", () => {
    window.history.length > 1 ? window.history.back() : window.location.replace("about:blank");
  });
  document.getElementById("kp-proceed").addEventListener("click", () => {
    kingphisherProceedAnyway = true;
    overlay.remove();
  });
}

function attachCredentialProtection() {
  document.addEventListener(
    "submit",
    async (event) => {
      const form = event.target;
      if (!(form instanceof HTMLFormElement)) return;
      if (!isCredentialForm(form)) return;
      if (form.dataset.kingphisherAllowed === "true") return;

      event.preventDefault();
      event.stopImmediatePropagation();

      const result = await ensureScan();
      if (["Phishing", "Suspicious"].includes(result.prediction)) {
        showSecurityWarning(result, true);
        return;
      }

      form.dataset.kingphisherAllowed = "true";
      form.submit();
    },
    true
  );
}

function isCredentialForm(form) {
  const hasPassword = Boolean(form.querySelector('input[type="password"]'));
  const hasEmail = Boolean(form.querySelector('input[type="email"], input[name*="email" i]'));
  const hasLoginText = /login|signin|sign in|account|password|credential/i.test(
    `${form.id} ${form.name} ${form.action} ${form.textContent}`
  );

  return hasPassword || hasEmail || hasLoginText;
}

function ensureScan() {
  if (kingphisherScan) return Promise.resolve(kingphisherScan);

  return new Promise((resolve) => {
    chrome.runtime.sendMessage(
      { type: "SCAN_URL", url: window.location.href },
      (response) => {
        if (response?.ok) {
          kingphisherScan = response.result;
          resolve(response.result);
          return;
        }

        resolve({
          prediction: "Suspicious",
          risk_score: 0.5,
          confidence: 50,
          reasons: [response?.error || "Backend scan unavailable during credential submission"]
        });
      }
    );
  });
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
