import { useEffect, useMemo, useState } from "react";
import Header from "./components/Header";
import Scan from "./pages/Scan";
import Dashboard from "./pages/Dashboard";

const API_BASE = "http://127.0.0.1:5000";

const NAV_ITEMS = [
  { id: "dashboard", label: "Dashboard", marker: "01" },
  { id: "url", label: "URL Scanner", marker: "02" },
  { id: "ocr", label: "OCR Scanner", marker: "03" },
  { id: "qr", label: "QR Scanner", marker: "04" },
  { id: "history", label: "Detection History", marker: "05" },
  { id: "analytics", label: "Analytics", marker: "06" },
  { id: "extension", label: "Browser Extension", marker: "07" },
];

function App() {
  const [page, setPage] = useState("dashboard");
  const [history, setHistory] = useState([]);
  const [toast, setToast] = useState(null);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState("");

  const notify = (message, type = "success") => {
    setToast({ message, type, id: Date.now() });
    window.setTimeout(() => setToast(null), 3400);
  };

  const refreshHistory = async () => {
    setHistoryLoading(true);
    setHistoryError("");
    try {
      const response = await fetch(`${API_BASE}/api/history?page_size=250&sort=date&direction=desc`);
      const data = await response.json();
      if (!response.ok) throw new Error(data?.reasons?.[0] || "Unable to load scan history");
      setHistory((data.items || []).map(normalizeHistoryRecord));
    } catch (error) {
      setHistoryError(error.message);
    } finally {
      setHistoryLoading(false);
    }
  };

  useEffect(() => {
    refreshHistory();
    const timer = window.setInterval(refreshHistory, 15000);
    return () => window.clearInterval(timer);
  }, []);

  const analytics = useMemo(() => {
    const total = history.length;
    const phishing = history.filter((item) => item.result === "Phishing").length;
    const suspicious = history.filter((item) => item.result === "Suspicious").length;
    const safe = history.filter((item) => item.result === "Safe").length;
    const ocrScans = history.filter((item) => item.mode === "ocr").length;
    const qrScans = history.filter((item) => item.mode === "qr").length;
    const browserHistoryScans = history.filter((item) => item.mode === "browser_history").length;
    const averageRisk = total
      ? history.reduce((sum, item) => sum + Number(item.riskScore || 0), 0) / total
      : 0;
    const blocked = phishing + suspicious;
    const safeRate = total ? Math.round((safe / total) * 100) : 100;

    return { total, phishing, suspicious, safe, averageRisk, blocked, safeRate, ocrScans, qrScans, browserHistoryScans };
  }, [history]);

  const renderPage = () => {
    if (page === "dashboard") {
      return <Dashboard history={history} analytics={analytics} setPage={setPage} refreshHistory={refreshHistory} />;
    }

    if (["url", "ocr", "qr"].includes(page)) {
      return (
        <Scan
          modePreset={page}
          history={history}
          setHistory={setHistory}
          notify={notify}
          onScanComplete={refreshHistory}
        />
      );
    }

    if (page === "history") {
      return (
        <HistoryPage
          history={history}
          loading={historyLoading}
          error={historyError}
          refreshHistory={refreshHistory}
        />
      );
    }

    if (page === "analytics") {
      return <AnalyticsPage analytics={analytics} history={history} />;
    }

    return <ExtensionPage />;
  };

  return (
    <div className="min-h-screen bg-app text-slate-100">
      <div className="security-grid" />
      <div className="relative z-10 flex min-h-screen">
        <aside className="sidebar-shell hidden w-72 shrink-0 px-4 py-5 lg:block">
          <div className="brand-block">
            <div className="brand-mark">KP</div>
            <div>
              <div className="text-xs font-semibold uppercase tracking-[0.28em] text-cyan-300">
                KingPhisher
              </div>
              <div className="mt-1 text-xl font-bold text-white">Security Command</div>
            </div>
          </div>

          <div className="mt-6 rounded-md border border-slate-800 bg-slate-950/55 p-3">
            <div className="flex items-center justify-between text-xs text-slate-500">
              <span>Threat posture</span>
              <span>{analytics.safeRate}% clean</span>
            </div>
            <div className="mt-3 h-2 overflow-hidden rounded-full bg-slate-800">
              <div className="h-full rounded-full bg-cyan-300 progress-fill" style={{ width: `${analytics.safeRate}%` }} />
            </div>
          </div>

          <nav className="mt-6 space-y-1">
            {NAV_ITEMS.map((item) => (
              <button
                key={item.id}
                onClick={() => setPage(item.id)}
                className={`nav-item ${page === item.id ? "nav-item-active" : ""}`}
              >
                <span className="nav-marker">{item.marker}</span>
                <span>{item.label}</span>
              </button>
            ))}
          </nav>
        </aside>

        <div className="flex min-w-0 flex-1 flex-col">
          <Header navItems={NAV_ITEMS} page={page} setPage={setPage} analytics={analytics} />
          <main className="flex-1 px-4 py-6 sm:px-6 lg:px-8">{renderPage()}</main>
        </div>
      </div>

      {toast && (
        <div className={`toast ${toast.type === "error" ? "toast-error" : "toast-success"}`}>
          <span className="toast-dot" />
          <span>{toast.message}</span>
        </div>
      )}
    </div>
  );
}

function HistoryPage({ history, loading, error, refreshHistory }) {
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("All");
  const [sortBy, setSortBy] = useState("date");

  const visibleHistory = useMemo(() => {
    const search = query.trim().toLowerCase();
    const filtered = history.filter((item) => {
      const matchesSearch = !search || item.url.toLowerCase().includes(search);
      const matchesStatus = statusFilter === "All" || item.result === statusFilter;
      return matchesSearch && matchesStatus;
    });

    return [...filtered].sort((a, b) => {
      if (sortBy === "risk") return Number(b.riskScore || 0) - Number(a.riskScore || 0);
      return new Date(b.timestamp || 0).getTime() - new Date(a.timestamp || 0).getTime();
    });
  }, [history, query, statusFilter, sortBy]);

  return (
    <section className="space-y-6">
      <PageTitle
        eyebrow="Case management"
        title="Detection History"
        text="Search, filter, and review every persisted scan from the web UI and browser extension."
      />

      <div className="security-card">
        <div className="history-toolbar">
          <input
            className="security-input"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search website URL"
          />
          <select className="security-select" value={sortBy} onChange={(event) => setSortBy(event.target.value)}>
            <option value="date">Sort by Date</option>
            <option value="risk">Sort by Risk</option>
          </select>
          <button onClick={refreshHistory} className="secondary-action" disabled={loading}>
            {loading ? "Refreshing" : "Refresh"}
          </button>
        </div>

        <div className="mt-4 flex flex-wrap gap-2">
          {["All", "Safe", "Suspicious", "Phishing"].map((status) => (
            <button
              key={status}
              onClick={() => setStatusFilter(status)}
              className={`filter-chip ${statusFilter === status ? "filter-chip-active" : ""}`}
            >
              {status === "All" ? "All Statuses" : status}
            </button>
          ))}
        </div>

        {error && <div className="mt-5 rounded-md border border-rose-500/40 bg-rose-500/10 p-4 text-sm text-rose-100">{error}</div>}
      </div>

      <div className="security-card overflow-hidden p-0">
        {visibleHistory.length === 0 ? (
          <EmptyState title="No detections found" text="Run a scan or adjust the current filters." />
        ) : (
          <div className="overflow-x-auto">
            <table className="history-table min-w-full text-sm">
              <thead>
                <tr>
                  <th>Website URL</th>
                  <th>Timestamp</th>
                  <th>Risk Score</th>
                  <th>Status</th>
                  <th>Module</th>
                  <th>Recommendation</th>
                </tr>
              </thead>
              <tbody>
                {visibleHistory.map((item, index) => (
                  <tr key={`${item.url}-${index}`} className="transition-colors hover:bg-slate-900/45">
                    <td className="max-w-md break-all font-semibold text-slate-100">{item.url}</td>
                    <td className="whitespace-nowrap text-slate-300">{formatTimestamp(item.timestamp)}</td>
                    <td className="font-bold text-slate-100">{formatScore(item.riskScore)}</td>
                    <td><RiskBadge prediction={item.result} /></td>
                    <td className="whitespace-nowrap text-slate-300">{item.modeLabel || item.mode}</td>
                    <td className="max-w-sm text-slate-300">{item.recommendation}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}

function normalizeHistoryRecord(item) {
  const result = item.status || item.prediction || item.result || "Suspicious";
  return {
    id: item.id,
    url: item.url || item.decoded_url || "Uploaded image",
    timestamp: item.timestamp || item.scanned_at,
    mode: item.scan_type || item.mode || "url",
    modeLabel: labelForMode(item.scan_type || item.mode, item.source),
    result,
    confidence: item.confidence,
    riskScore: item.risk_score ?? item.riskScore,
    reasons: item.reasons || [],
    details: item.details || [],
    extractedText: item.extracted_text || "",
    decodedUrl: item.decoded_url || "",
    recommendation: item.recommendation || recommendationFor(result, item.risk_score ?? item.riskScore),
    raw: item,
  };
}

function labelForMode(mode, source) {
  if (mode === "browser_history" || source === "browser_history") return "Browser History";
  if (mode === "ocr") return "OCR Scanner";
  if (mode === "qr") return "QR Scanner";
  if (mode === "html") return "HTML Analyzer";
  return "URL Scanner";
}

function recommendationFor(prediction, score) {
  if (prediction === "Phishing" || Number(score) >= 0.6) {
    return "Block access and avoid submitting credentials or payment information.";
  }
  if (prediction === "Suspicious" || Number(score) >= 0.35) {
    return "Verify the sender, domain, and page intent before continuing.";
  }
  return "No immediate phishing indicators were detected.";
}

function AnalyticsPage({ analytics, history }) {
  const bars = [
    { label: "Safe", value: analytics.safe, color: "bg-emerald-400" },
    { label: "Suspicious", value: analytics.suspicious, color: "bg-amber-400" },
    { label: "Phishing", value: analytics.phishing, color: "bg-rose-500" },
  ];

  return (
    <section className="space-y-6">
      <PageTitle
        eyebrow="Detection telemetry"
        title="Analytics"
        text="Live readout of scanner volume, outcome distribution, and average ensemble risk."
      />

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Total Scans" value={analytics.total} tone="cyan" />
        <StatCard label="Safe Verdicts" value={analytics.safe} tone="green" />
        <StatCard label="Needs Review" value={analytics.suspicious} tone="amber" />
        <StatCard label="Blocked" value={analytics.phishing} tone="red" />
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.15fr_0.85fr]">
        <div className="security-card">
          <div className="flex items-center justify-between">
            <h3 className="section-title">Detection Distribution</h3>
            <span className="status-pill">In-session</span>
          </div>
          <div className="mt-6 space-y-5">
            {bars.map((bar) => {
              const width = analytics.total ? (bar.value / analytics.total) * 100 : 0;
              return (
                <div key={bar.label}>
                  <div className="mb-2 flex justify-between text-sm">
                    <span className="text-slate-300">{bar.label}</span>
                    <span className="text-slate-500">{bar.value} detections</span>
                  </div>
                  <div className="h-3 overflow-hidden rounded-full bg-slate-800">
                    <div className={`h-full rounded-full ${bar.color} progress-fill`} style={{ width: `${width}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <div className="security-card">
          <h3 className="section-title">Average Risk</h3>
          <RiskDial score={analytics.averageRisk} />
          <p className="mt-4 text-sm leading-6 text-slate-400">
            Computed from URL, OCR, QR, and ensemble results captured in the current operator session.
          </p>
        </div>
      </div>

      <div className="security-card">
        <h3 className="section-title">Recent Activity</h3>
        <div className="mt-4 grid gap-3">
          {history.slice(0, 6).map((item, index) => (
            <div key={`${item.url}-${index}`} className="activity-row">
              <div className="min-w-0">
                <div className="truncate text-sm font-semibold text-slate-200">{item.url}</div>
                <div className="text-xs text-slate-500">{item.modeLabel || item.mode}</div>
              </div>
              <div className="flex items-center gap-3">
                <span className="hidden text-sm text-slate-500 sm:inline">Risk {formatScore(item.riskScore)}</span>
                <RiskBadge prediction={item.result} />
              </div>
            </div>
          ))}
          {history.length === 0 && <EmptyState title="No analytics data" text="Run scans to populate trend panels." />}
        </div>
      </div>
    </section>
  );
}

function ExtensionPage() {
  const steps = [
    "Page URL is captured by the extension runtime.",
    "The backend ensemble evaluates URL, HTML, and visible indicators.",
    "Verdict is rendered in the popup and page overlay.",
    "Credential entry is discouraged or blocked for high-risk pages.",
  ];

  return (
    <section className="space-y-6">
      <PageTitle
        eyebrow="Browser protection"
        title="Browser Extension"
        text="Operator-grade endpoint workflow for real-time browsing protection and scan escalation."
      />
      <div className="grid gap-4 xl:grid-cols-[1fr_0.9fr]">
        <div className="security-card">
          <div className="flex items-center justify-between">
            <h3 className="section-title">Protection Workflow</h3>
            <span className="status-pill">Chrome ready</span>
          </div>
          <div className="mt-5 space-y-3">
            {steps.map((step, index) => (
              <div key={step} className="workflow-row">
                <div className="step-index">{index + 1}</div>
                <div className="text-sm leading-6 text-slate-300">{step}</div>
              </div>
            ))}
          </div>
        </div>
        <div className="security-card">
          <h3 className="section-title">Response Policy</h3>
          <div className="mt-5 grid gap-3">
            <StatusRow prediction="Safe" text="Allow navigation with passive monitoring." />
            <StatusRow prediction="Suspicious" text="Warn the user and recommend manual verification." />
            <StatusRow prediction="Phishing" text="Show a high-severity warning and block credential submission." />
          </div>
        </div>
      </div>
    </section>
  );
}

function PageTitle({ eyebrow, title, text }) {
  return (
    <div>
      <div className="text-xs font-semibold uppercase tracking-[0.22em] text-cyan-300">{eyebrow}</div>
      <h1 className="mt-2 text-3xl font-bold tracking-tight text-white sm:text-4xl">{title}</h1>
      <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-400">{text}</p>
    </div>
  );
}

function StatCard({ label, value, tone }) {
  return (
    <div className={`security-card stat-card stat-${tone}`}>
      <div className="text-sm text-slate-400">{label}</div>
      <div className="animated-stat mt-3 text-4xl font-bold text-white">{value}</div>
    </div>
  );
}

function RiskBadge({ prediction }) {
  const className =
    prediction === "Phishing"
      ? "risk-badge risk-red"
      : prediction === "Suspicious"
        ? "risk-badge risk-yellow"
        : "risk-badge risk-green";
  return <span className={className}>{prediction || "Unknown"}</span>;
}

function RiskDial({ score }) {
  const value = clampScore(score);
  const degrees = Math.round(value * 360);
  return (
    <div className="mt-6 flex items-center justify-center">
      <div
        className="risk-dial"
        style={{ background: `conic-gradient(${riskColor(value)} ${degrees}deg, #1e293b ${degrees}deg)` }}
      >
        <div className="risk-dial-inner">
          <div className="text-3xl font-bold">{value.toFixed(2)}</div>
          <div className="text-xs uppercase text-slate-500">Risk</div>
        </div>
      </div>
    </div>
  );
}

function StatusRow({ prediction, text }) {
  return (
    <div className="activity-row">
      <div className="text-sm leading-6 text-slate-300">{text}</div>
      <RiskBadge prediction={prediction} />
    </div>
  );
}

function EmptyState({ title, text }) {
  return (
    <div className="p-10 text-center">
      <div className="text-lg font-semibold text-slate-200">{title}</div>
      <p className="mt-2 text-sm text-slate-500">{text}</p>
    </div>
  );
}

function clampScore(score) {
  return Math.max(0, Math.min(1, Number(score) || 0));
}

function formatScore(score) {
  return score === null || score === undefined ? "n/a" : clampScore(score).toFixed(3);
}

function formatTimestamp(timestamp) {
  if (!timestamp) return "n/a";
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return timestamp;
  return date.toLocaleString();
}

function riskColor(value) {
  if (value >= 0.6) return "#f43f5e";
  if (value >= 0.35) return "#f59e0b";
  return "#34d399";
}

export default App;
