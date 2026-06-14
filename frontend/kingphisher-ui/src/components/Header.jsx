export default function Header({ navItems, page, setPage, analytics }) {
  const active = navItems.find((item) => item.id === page);

  return (
    <header className="sticky top-0 z-30 border-b border-slate-800/90 bg-[#0b1220]/88 px-4 py-4 backdrop-blur-xl sm:px-6 lg:px-8">
      <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
        <div className="min-w-0">
          <div className="text-xs uppercase tracking-[0.22em] text-slate-500">Active console</div>
          <div className="mt-1 flex flex-wrap items-center gap-3">
            <div className="text-xl font-semibold text-white">{active?.label || "Dashboard"}</div>
            <span className="status-pill">Backend monitor ready</span>
          </div>
        </div>

        <div className="flex gap-2 overflow-x-auto pb-1 lg:hidden">
          {navItems.map((item) => (
            <button
              key={item.id}
              onClick={() => setPage(item.id)}
              className={`mobile-nav-item ${page === item.id ? "mobile-nav-active" : ""}`}
            >
              {item.label}
            </button>
          ))}
        </div>

        <div className="hidden items-center gap-3 xl:flex">
          <HeaderMetric label="Scans" value={analytics?.total ?? 0} />
          <HeaderMetric label="Blocked" value={analytics?.blocked ?? 0} />
          <HeaderMetric label="Avg Risk" value={(analytics?.averageRisk ?? 0).toFixed(2)} />
        </div>
      </div>
    </header>
  );
}

function HeaderMetric({ label, value }) {
  return (
    <div className="rounded-md border border-slate-800 bg-slate-950/55 px-4 py-2">
      <div className="text-[11px] uppercase tracking-wide text-slate-500">{label}</div>
      <div className="mt-1 text-sm font-bold text-slate-100">{value}</div>
    </div>
  );
}
