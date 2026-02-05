export default function Dashboard({ history, setPage }) {
  return (
    <div className="p-8">

      {/* BACK TO HOME */}
      <button
        onClick={() => setPage("home")}
        className="mb-6 px-4 py-2 rounded-lg bg-slate-700 hover:bg-slate-600 transition"
      >
        ← Back to Home
      </button>

      <h2 className="text-3xl font-bold mb-6">📊 Scan History</h2>

      {history.length === 0 ? (
        <p className="text-slate-400">No scans yet.</p>
      ) : (
        <table className="w-full bg-slate-800 rounded-xl overflow-hidden">
          <thead>
            <tr className="text-left text-slate-400 border-b border-slate-700">
              <th className="p-4">URL</th>
              <th>Status</th>
              <th>Confidence</th>
            </tr>
          </thead>
          <tbody>
            {history.map((item, i) => (
              <tr key={i} className="border-b border-slate-700">
                <td className="p-4 break-all">{item.url}</td>
                <td
                  className={
                    item.result === "Phishing"
                      ? "text-red-400"
                      : item.result === "Suspicious"
                      ? "text-yellow-400"
                      : "text-green-400"
                  }
                >
                  {item.result}
                </td>
                <td>{item.confidence}%</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
