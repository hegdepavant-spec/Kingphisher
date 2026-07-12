import { useState } from "react";

const API_BASE = "http://127.0.0.1:5000";

const MODE_CONFIG = {
  url: {
    label: "URL Scanner",
    eyebrow: "URL intelligence",
    description: "Inspect a destination URL with URL ML, explainable HTML analysis, and weighted ensemble scoring.",
    endpoint: "/api/ensemble",
    inputTitle: "Target destination",
  },
  ocr: {
    label: "OCR Scanner",
    eyebrow: "Visual text intelligence",
    description: "Upload a webpage screenshot to extract visible text and detect phishing language.",
    endpoint: "/api/ocr",
    inputTitle: "Screenshot artifact",
  },
  qr: {
    label: "QR Scanner",
    eyebrow: "QR payload intelligence",
    description: "Decode QR codes, extract embedded URLs, and run the destination through the detection pipeline.",
    endpoint: "/api/qr",
    inputTitle: "QR artifact",
  },
};

export default function Scan({ modePreset = "url", setHistory, notify, onScanComplete }) {
  const config = MODE_CONFIG[modePreset] || MODE_CONFIG.url;
  const [url, setUrl] = useState("");
  const [image, setImage] = useState(null);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const needsUrl = modePreset === "url";
  const needsImage = modePreset === "ocr" || modePreset === "qr";

  const scan = async () => {
    if (needsUrl && !url.trim()) {
      setError("Enter a URL before running detection.");
      notify?.("Enter a URL before running detection.", "error");
      return;
    }

    if (needsImage && !image) {
      setError("Upload an image before running detection.");
      notify?.("Upload an image before running detection.", "error");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      let data;
      if (modePreset === "url") {
        data = await callJson(config.endpoint, { url: url.trim() });
      } else {
        const formData = new FormData();
        formData.append("image", image);
        data = await callForm(config.endpoint, formData);
      }

      const entry = normalizeResult(data, modePreset, config.label, url, image);
      setHistory((currentHistory) => [entry, ...currentHistory]);
      setResult(entry);
      notify?.(`${config.label} completed: ${entry.result}`, entry.result === "Phishing" ? "error" : "success");
      onScanComplete?.();
    } catch (err) {
      setError(err.message);
      notify?.(err.message, "error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="space-y-6">
      <div className="scanner-header">
        <div>
          <div className="text-xs font-semibold uppercase tracking-[0.22em] text-cyan-300">
            {config.eyebrow}
          </div>
          <h1 className="mt-2 text-3xl font-bold text-white sm:text-4xl">{config.label}</h1>
          <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-400">{config.description}</p>
        </div>
        <div className="scanner-sla">
          <span className="live-dot" />
          <span>Real-time scoring pipeline</span>
        </div>
      </div>

      <div className="grid gap-5 xl:grid-cols-[0.82fr_1.18fr]">
        <div className="security-card h-fit">
          <div className="flex items-center justify-between">
            <h2 className="section-title">{config.inputTitle}</h2>
            <span className="status-pill">Secure POST</span>
          </div>

          {needsUrl && (
            <label className="mt-5 block">
              <span className="form-label">Target URL</span>
              <input
                className="security-input"
                placeholder="https://example.com/login"
                value={url}
                onChange={(event) => setUrl(event.target.value)}
                onKeyDown={(event) => event.key === "Enter" && scan()}
              />
            </label>
          )}

          {needsImage && (
            <label className="mt-5 block">
              <span className="form-label">{modePreset === "qr" ? "QR image" : "Screenshot image"}</span>
              <input
                className="security-input file:mr-4 file:rounded-md file:border-0 file:bg-cyan-500 file:px-4 file:py-2 file:text-sm file:font-semibold file:text-slate-950"
                type="file"
                accept="image/*"
                onChange={(event) => setImage(event.target.files?.[0] || null)}
              />
            </label>
          )}

          {image && (
            <div className="mt-4 rounded-md border border-slate-800 bg-slate-950/55 p-4 text-sm text-slate-400">
              <div className="text-xs uppercase tracking-wide text-slate-500">Selected artifact</div>
              <div className="mt-1 break-all font-semibold text-slate-200">{image.name}</div>
            </div>
          )}

          {loading && <LoadingPanel />}

          {error && (
            <div className="mt-5 rounded-md border border-rose-500/40 bg-rose-500/10 p-4 text-sm text-rose-200">
              {error}
            </div>
          )}

          <div className="mt-6 flex flex-col gap-3 sm:flex-row">
            <button onClick={scan} disabled={loading} className="primary-action">
              {loading ? "Scanning" : "Run Detection"}
            </button>
            <button
              onClick={() => {
                setUrl("");
                setImage(null);
                setResult(null);
                setError("");
              }}
              className="secondary-action"
            >
              Reset
            </button>
          </div>

          <div className="mt-6 grid gap-3">
            <PipelineStep label="Input validation" active={Boolean(url || image)} />
            <PipelineStep label="Model scoring" active={loading || Boolean(result)} />
            <PipelineStep label="Recommendation generated" active={Boolean(result)} />
          </div>
        </div>

        <ResultWorkspace result={result} loading={loading} modeLabel={config.label} />
      </div>
    </section>
  );
}

async function callJson(endpoint, body) {
  const response = await fetch(`${API_BASE}${endpoint}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data?.reasons?.[0] || "Request failed");
  return data;
}

async function callForm(endpoint, formData) {
  const response = await fetch(`${API_BASE}${endpoint}`, {
    method: "POST",
    body: formData,
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data?.reasons?.[0] || "Request failed");
  return data;
}

function normalizeResult(data, mode, modeLabel, url, image) {
  const details = data.details || [];
  const prediction = data.prediction || data.verdict || "Suspicious";
  const riskScore = data.risk_score ?? data.score ?? data.final_score;
  return {
    url: data.decoded_url || url || image?.name || "Uploaded image",
    mode,
    modeLabel,
    result: prediction,
    confidence: data.confidence,
    riskScore,
    reasons: data.reasons || data.explanation || [],
    details,
    extractedText: data.extracted_text || "",
    decodedUrl: data.decoded_url || "",
    recommendation: recommendationFor(prediction, riskScore),
    raw: data,
  };
}

function recommendationFor(prediction, score) {
  if (prediction === "Phishing" || Number(score) >= 0.6) {
    return "Block access, avoid credential entry, and use the official website or application through a trusted bookmark.";
  }
  if (prediction === "Suspicious" || Number(score) >= 0.35) {
    return "Proceed only after verifying the sender, domain, and page intent. Do not submit passwords or payment data.";
  }
  return "No immediate phishing indicators were detected. Continue monitoring if the page asks for sensitive data.";
}

function LoadingPanel() {
  return (
    <div className="mt-5 rounded-md border border-cyan-400/20 bg-cyan-400/10 p-4">
      <div className="mb-3 flex items-center justify-between text-sm">
        <span className="text-cyan-100">Running detection pipeline</span>
        <span className="text-cyan-300">Analyzing</span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-slate-800">
        <div className="loading-progress h-full rounded-full bg-cyan-300" />
      </div>
    </div>
  );
}

function PipelineStep({ label, active }) {
  return (
    <div className={`pipeline-step ${active ? "pipeline-step-active" : ""}`}>
      <span className="pipeline-dot" />
      <span>{label}</span>
    </div>
  );
}

function ResultWorkspace({ result, loading, modeLabel }) {
  if (loading) {
    return (
      <div className="security-card min-h-[520px]">
        <ResultSkeleton />
      </div>
    );
  }

  if (!result) {
    return (
      <div className="security-card min-h-[520px]">
        <div className="flex h-full min-h-[460px] flex-col items-center justify-center text-center">
          <div className="radar-pulse" />
          <h2 className="mt-8 text-2xl font-bold text-white">Awaiting detection input</h2>
          <p className="mt-3 max-w-md text-sm leading-6 text-slate-500">
            Run {modeLabel.toLowerCase()} to generate a full detection results page with scores, reasons, and recommendations.
          </p>
        </div>
      </div>
    );
  }

  return <DetectionResults result={result} />;
}

function DetectionResults({ result }) {
  const urlModule = getModule(result.details, "URL");
  const ocrModule = getModule(result.details, "OCR");
  const htmlModule = getModule(result.details, "HTML");

  return (
    <div className="space-y-5">
      <div className="result-banner">
        <div>
          <div className="text-xs font-semibold uppercase tracking-[0.22em] text-slate-400">Detection result</div>
          <div className="mt-2 flex flex-wrap items-center gap-3">
            <h2 className="text-3xl font-bold text-white">{result.result}</h2>
            <RiskBadge prediction={result.result} />
          </div>
          <p className="mt-3 break-all text-sm text-slate-400">{result.url}</p>
        </div>
        <RiskScore score={result.riskScore} />
      </div>

      {result.decodedUrl && (
        <InfoPanel title="Decoded QR URL" value={result.decodedUrl} />
      )}

      <div className="grid gap-4 lg:grid-cols-3">
        <AnalysisCard
          title="URL Analysis"
          score={urlModule?.result?.risk_score}
          prediction={urlModule?.result?.prediction}
          reasons={urlModule?.result?.reasons}
        />
        <AnalysisCard
          title="OCR Analysis"
          score={ocrModule?.result?.risk_score ?? (result.extractedText ? result.riskScore : null)}
          prediction={ocrModule?.result?.prediction ?? (result.extractedText ? result.result : null)}
          reasons={ocrModule?.result?.reasons ?? (result.extractedText ? result.reasons : null)}
          extractedText={result.extractedText}
        />
        <AnalysisCard
          title="HTML Analysis"
          score={htmlModule?.result?.risk_score}
          prediction={htmlModule?.result?.prediction}
          reasons={htmlModule?.result?.reasons}
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-[0.8fr_1.2fr]">
        <div className="security-card">
          <div className="flex items-center justify-between">
            <h3 className="section-title">Final Ensemble Score</h3>
            <RiskBadge prediction={result.result} />
          </div>
          <RiskScore score={result.riskScore} large />
          <p className="mt-4 text-sm text-slate-400">
            Confidence: <span className="font-semibold text-slate-200">{result.confidence ?? 0}%</span>
          </p>
        </div>
        <div className="security-card">
          <h3 className="section-title">Security Recommendation</h3>
          <p className="mt-4 text-sm leading-6 text-slate-300">{result.recommendation}</p>
          <div className="mt-5 rounded-md border border-slate-800 bg-slate-950/60 p-4">
            <div className="mb-2 text-sm font-semibold text-slate-200">Primary reasons</div>
            <ReasonList reasons={result.reasons} />
          </div>
        </div>
      </div>
    </div>
  );
}

function AnalysisCard({ title, score, prediction, reasons, extractedText }) {
  const hasData = score !== null && score !== undefined;
  return (
    <div className="security-card">
      <div className="flex items-start justify-between gap-4">
        <h3 className="section-title">{title}</h3>
        {prediction && <RiskBadge prediction={prediction} />}
      </div>
      {hasData ? (
        <>
          <div className="mt-5">
            <ProgressScore score={score} />
          </div>
          {extractedText && (
            <div className="mt-5">
              <div className="mb-2 text-sm font-semibold text-slate-300">Extracted Text</div>
              <div className="max-h-36 overflow-auto rounded-md bg-slate-950/70 p-3 text-xs leading-5 text-slate-400">
                {extractedText}
              </div>
            </div>
          )}
          <div className="mt-5">
            <div className="mb-2 text-sm font-semibold text-slate-300">Reasons</div>
            <ReasonList reasons={reasons} />
          </div>
        </>
      ) : (
        <div className="mt-5 rounded-md border border-dashed border-slate-700 p-5 text-sm text-slate-500">
          This module was not part of the current scan.
        </div>
      )}
    </div>
  );
}

function ProgressScore({ score }) {
  const value = Math.max(0, Math.min(1, Number(score) || 0));
  const color = value >= 0.6 ? "bg-rose-500" : value >= 0.35 ? "bg-amber-400" : "bg-emerald-400";
  return (
    <>
      <div className="mb-2 flex justify-between text-sm">
        <span className="text-slate-400">Score</span>
        <span className="font-semibold text-slate-200">{value.toFixed(3)}</span>
      </div>
      <div className="h-3 overflow-hidden rounded-full bg-slate-800">
        <div className={`h-full rounded-full ${color} progress-fill`} style={{ width: `${value * 100}%` }} />
      </div>
    </>
  );
}

function RiskScore({ score, large = false }) {
  const value = Math.max(0, Math.min(1, Number(score) || 0));
  const degrees = Math.round(value * 360);
  const color = value >= 0.6 ? "#f43f5e" : value >= 0.35 ? "#f59e0b" : "#34d399";
  return (
    <div
      className={large ? "risk-score-large" : "risk-score"}
      style={{ background: `conic-gradient(${color} ${degrees}deg, #1e293b ${degrees}deg)` }}
    >
      <div className="risk-score-inner">
        <span>{value.toFixed(3)}</span>
        <small>Risk</small>
      </div>
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

function ReasonList({ reasons }) {
  const items = reasons?.length ? reasons : ["No module-specific reason was returned."];
  return (
    <ul className="space-y-2 text-sm text-slate-400">
      {items.slice(0, 6).map((reason, index) => (
        <li key={`${reason}-${index}`} className="flex gap-2">
          <span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-cyan-300" />
          <span>{reason}</span>
        </li>
      ))}
    </ul>
  );
}

function InfoPanel({ title, value }) {
  return (
    <div className="security-card">
      <h3 className="section-title">{title}</h3>
      <p className="mt-3 break-all rounded-md bg-slate-950/60 p-4 text-sm text-slate-300">{value}</p>
    </div>
  );
}

function ResultSkeleton() {
  return (
    <div className="space-y-4">
      <div className="skeleton h-28" />
      <div className="grid gap-4 md:grid-cols-3">
        <div className="skeleton h-48" />
        <div className="skeleton h-48" />
        <div className="skeleton h-48" />
      </div>
      <div className="skeleton h-36" />
    </div>
  );
}

function getModule(details, label) {
  return details.find((detail) => detail.module?.toLowerCase().includes(label.toLowerCase()));
}
