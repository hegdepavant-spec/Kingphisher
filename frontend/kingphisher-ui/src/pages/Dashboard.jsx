export default function Dashboard({ history, analytics, setPage, refreshHistory }) {
  const recent = history.slice(0, 6);

  return (
    <section className="space-y-6">
      <div className="dashboard-hero">
        <div>
          <div className="text-xs font-semibold uppercase tracking-[0.24em] text-cyan-300">
            Threat detection platform
          </div>
          <h1 className="mt-3 max-w-4xl text-4xl font-bold tracking-tight text-white lg:text-5xl">
            Unified phishing intelligence for URLs, screenshots, HTML, and QR payloads.
          </h1>
          <p className="mt-4 max-w-2xl text-sm leading-6 text-slate-400">
            KingPhisher combines URL ML, OCR text classification, HTML inspection, QR decoding, and ensemble scoring into one operator-ready workspace.
          </p>
          <div className="mt-6 flex flex-wrap gap-3">
            <button className="primary-action" onClick={() => setPage("url")}>Run URL scan</button>
            <button className="secondary-action" onClick={() => setPage("history")}>Review history</button>
            <button className="secondary-action" onClick={refreshHistory}>Refresh data</button>
          </div>
        </div>

        <div className="hero-status">
          <div className="flex items-center justify-between">
            <div className="text-sm text-slate-400">Operational state</div>
            <span className="status-pill">Live</span>
          </div>
          <div className="mt-3 text-2xl font-bold text-emerald-300">Protected</div>
          <div className="mt-5 grid grid-cols-3 gap-2 text-center">
            <MiniMetric label="Safe" value={analytics.safe} />
            <MiniMetric label="Review" value={analytics.suspicious} />
            <MiniMetric label="Blocked" value={analytics.phishing} />
          </div>
          <div className="mt-5 h-2 overflow-hidden rounded-full bg-slate-800">
            <div className="h-full rounded-full bg-cyan-300 progress-fill" style={{ width: `${analytics.safeRate}%` }} />
          </div>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <Metric label="Total Scans" value={analytics.total} accent="cyan" detail="All persisted detections" />
        <Metric label="Safe Sites" value={analytics.safe} accent="green" detail={`${analytics.safeRate}% clean rate`} />
        <Metric label="Phishing Sites" value={analytics.phishing} accent="red" detail="Confirmed high risk" />
        <Metric label="Blocked Sites" value={analytics.blocked} accent="amber" detail="Suspicious and phishing" />
        <Metric label="OCR Scans" value={analytics.ocrScans} accent="green" detail="Screenshot text analysis" />
        <Metric label="QR Scans" value={analytics.qrScans} accent="cyan" detail="Decoded QR payloads" />
        <Metric label="Browser History" value={analytics.browserHistoryScans} accent="amber" detail="Extension history entries" />
        <Metric label="Average Risk" value={analytics.averageRisk.toFixed(2)} accent="red" detail="Mean risk score" />
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.2fr_0.8fr]">
        <div className="security-card">
          <div className="flex items-center justify-between gap-4">
            <h2 className="section-title">Scanner Launchpad</h2>
            <span className="status-pill">Detection modules</span>
          </div>
          <div className="mt-5 grid gap-4 md:grid-cols-3">
            <LaunchCard
              title="URL Scanner"
              text="Analyze lexical features, page signals, and ensemble verdicts."
              onClick={() => setPage("url")}
              accent="cyan"
              marker="URL"
            />
            <LaunchCard
              title="OCR Scanner"
              text="Extract screenshot text and classify phishing language."
              onClick={() => setPage("ocr")}
              accent="green"
              marker="OCR"
            />
            <LaunchCard
              title="QR Scanner"
              text="Decode QR destinations and route them through detection."
              onClick={() => setPage("qr")}
              accent="amber"
              marker="QR"
            />
          </div>
        </div>

        <div className="security-card">
          <div className="flex items-center justify-between">
            <h2 className="section-title">Risk Composition</h2>
            <span className="text-xs text-slate-500">{analytics.total} events</span>
          </div>
          <div className="mt-6 space-y-4">
            <RiskBar label="Safe" value={analytics.safe} total={analytics.total} color="bg-emerald-400" />
            <RiskBar label="Suspicious" value={analytics.suspicious} total={analytics.total} color="bg-amber-400" />
            <RiskBar label="Phishing" value={analytics.phishing} total={analytics.total} color="bg-rose-500" />
          </div>
          <div className="mt-6 risk-stack">
            <div className="bg-emerald-400" style={{ width: `${percent(analytics.safe, analytics.total)}%` }} />
            <div className="bg-amber-400" style={{ width: `${percent(analytics.suspicious, analytics.total)}%` }} />
            <div className="bg-rose-500" style={{ width: `${percent(analytics.phishing, analytics.total)}%` }} />
          </div>
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-[1fr_0.8fr]">
        <div className="security-card">
          <div className="flex items-center justify-between">
            <h2 className="section-title">Recent Detections</h2>
            <button onClick={() => setPage("history")} className="ghost-button">History</button>
          </div>
          <div className="mt-5 grid gap-3">
            {recent.length === 0 ? (
              <div className="empty-panel">
                No detections yet. Run a scan to populate operational history.
              </div>
            ) : (
              recent.map((item, index) => (
                <div key={`${item.url}-${index}`} className="detection-row">
                  <div className="min-w-0">
                    <div className="truncate text-sm font-semibold text-slate-200">{item.url}</div>
                    <div className="text-xs text-slate-400">{item.modeLabel || item.mode} · {formatTimestamp(item.timestamp)}</div>
                  </div>
                  <div className="flex items-center gap-4">
                    <span className="hidden text-sm text-slate-500 sm:inline">Risk {formatScore(item.riskScore)}</span>
                    <Badge prediction={item.result} />
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="security-card">
          <h2 className="section-title">Detection Coverage</h2>
          <div className="mt-5 grid gap-3">
            <CoverageRow label="URL intelligence" value="Lexical ML + reputation cues" />
            <CoverageRow label="OCR intelligence" value="Screenshot text extraction" />
            <CoverageRow label="HTML inspection" value="Form, script, and redirect signals" />
            <CoverageRow label="QR decoding" value="Embedded URL extraction" />
          </div>
        </div>
      </div>
    </section>
  );
}

function Metric({ label, value, accent, detail }) {
  return (
    <div className={`security-card metric-card metric-${accent}`}>
      <div className="text-sm text-slate-400">{label}</div>
      <div className="animated-stat mt-3 text-4xl font-bold text-white">{value}</div>
      <div className="mt-2 text-xs text-slate-500">{detail}</div>
    </div>
  );
}

function MiniMetric({ label, value }) {
  return (
    <div className="rounded-md border border-slate-800 bg-slate-950/55 p-3">
      <div className="text-lg font-bold text-white">{value}</div>
      <div className="mt-1 text-[11px] uppercase tracking-wide text-slate-500">{label}</div>
    </div>
  );
}

function LaunchCard({ title, text, onClick, accent, marker }) {
  return (
    <button onClick={onClick} className={`launch-card launch-${accent}`}>
      <div className="launch-orb">{marker}</div>
      <div className="mt-5 text-left text-lg font-semibold text-white">{title}</div>
      <p className="mt-2 text-left text-sm leading-6 text-slate-400">{text}</p>
      <div className="mt-5 text-left text-xs font-semibold uppercase tracking-wide text-cyan-300">Open module</div>
    </button>
  );
}

function RiskBar({ label, value, total, color }) {
  const width = total ? (value / total) * 100 : 0;
  return (
    <div>
      <div className="mb-2 flex justify-between text-sm">
        <span className="text-slate-300">{label}</span>
        <span className="text-slate-500">{value}</span>
      </div>
      <div className="h-3 overflow-hidden rounded-full bg-slate-800">
        <div className={`h-full rounded-full ${color} progress-fill`} style={{ width: `${width}%` }} />
      </div>
    </div>
  );
}

function CoverageRow({ label, value }) {
  return (
    <div className="rounded-md border border-slate-800 bg-slate-950/55 p-4">
      <div className="text-sm font-semibold text-slate-200">{label}</div>
      <div className="mt-1 text-xs text-slate-500">{value}</div>
    </div>
  );
}

function Badge({ prediction }) {
  const className =
    prediction === "Phishing"
      ? "risk-badge risk-red"
      : prediction === "Suspicious"
        ? "risk-badge risk-yellow"
        : "risk-badge risk-green";
  return <span className={className}>{prediction || "Unknown"}</span>;
}

function formatScore(score) {
  return score === null || score === undefined ? "n/a" : Math.max(0, Math.min(1, Number(score) || 0)).toFixed(3);
}

function formatTimestamp(timestamp) {
  if (!timestamp) return "n/a";
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return timestamp;
  return date.toLocaleString();
}

function percent(value, total) {
  return total ? (value / total) * 100 : 0;
}
