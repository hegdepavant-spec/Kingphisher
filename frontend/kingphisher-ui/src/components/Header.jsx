export default function Header({ setPage }) {
  return (
    <div className="flex justify-between items-center px-8 py-4 border-b border-slate-700">
      <h1
        onClick={() => setPage("home")}
        className="text-2xl font-bold cursor-pointer"
      >
        🛡️ KINGPHISHER
      </h1>

      <button
        onClick={() => setPage("dashboard")}
        className="px-4 py-2 rounded-lg bg-slate-700 hover:bg-slate-600 transition"
      >
        📊 Dashboard
      </button>
    </div>
  );
}
