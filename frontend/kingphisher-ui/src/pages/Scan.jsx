import { useState } from "react";

export default function Scan({ history, setHistory, setPage }) {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const scanUrl = async () => {
    if (!url) return;
    setLoading(true);

    const res = await fetch("http://127.0.0.1:5000/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    const data = await res.json();

    const entry = {
      url,
      result: data.prediction,
      confidence: data.confidence,
      reasons: data.reasons || [],
    };

    setHistory([entry, ...history]);
    setResult(entry);
    setLoading(false);
  };

  return (
    <div className="flex flex-col items-center mt-24 px-4">

      {/* BACK TO HOME */}
      <button
        onClick={() => setPage("home")}
        className="self-start mb-6 px-4 py-2 rounded-lg bg-slate-700 hover:bg-slate-600 transition"
      >
        ← Back to Home
      </button>

      <h2 className="text-3xl font-bold mb-6">Scan a Website URL</h2>

      {/* INPUT + REFRESH */}
      <div className="flex items-center gap-2 mb-4">
        <input
          className="w-[380px] p-4 rounded-xl bg-slate-700 outline-none"
          placeholder="Paste URL here and press Enter"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && scanUrl()}
        />

        <button
          onClick={() => {
            setUrl("");
            setResult(null);
          }}
          title="Clear"
          className="p-4 rounded-xl bg-slate-600 hover:bg-slate-500 transition"
        >
          🔄
        </button>
      </div>

      <button
        onClick={scanUrl}
        disabled={loading}
        className="px-6 py-3 rounded-lg bg-blue-600 hover:bg-blue-500 transition disabled:opacity-50"
      >
        {loading ? "Scanning..." : "Scan Now"}
      </button>

      {/* RESULT */}
      {result && (
        <div className="mt-10 w-[460px] p-6 rounded-2xl glass-card shadow-xl">

          <h3
            className={`text-2xl font-bold mb-2 text-center ${
              result.result === "Phishing"
                ? "text-red-400"
                : result.result === "Suspicious"
                ? "text-yellow-400"
                : "text-green-400"
            }`}
          >
            {result.result === "Phishing"
              ? "🚨 PHISHING DETECTED"
              : result.result === "Suspicious"
              ? "⚠️ SUSPICIOUS WEBSITE"
              : "✅ WEBSITE IS SAFE"}
          </h3>

          <p className="text-center text-slate-300 mb-4">
            Confidence: <span className="font-semibold">{result.confidence}%</span>
          </p>

          <div className="w-full bg-slate-700 rounded-full h-3 mb-5">
            <div
              className={`h-3 rounded-full ${
                result.result === "Phishing"
                  ? "bg-red-500"
                  : result.result === "Suspicious"
                  ? "bg-yellow-400"
                  : "bg-green-500"
              }`}
              style={{ width: `${result.confidence}%` }}
            />
          </div>

          <div>
            <h4 className="font-semibold mb-2 text-slate-200">
              Why was this result given?
            </h4>
            <ul className="list-disc list-inside text-slate-300 space-y-1">
              {result.reasons.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}
