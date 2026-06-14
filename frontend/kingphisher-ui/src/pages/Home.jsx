export default function Home({ setPage }) {
  return (
    <div className="flex flex-col items-center justify-center mt-28 px-4 text-center">
      
      
      <h1 className="kingphisher-title">KINGPHISHER</h1>

     
      <p className="kingphisher-subtitle">
        Protect yourself from phishing attacks.  
        Scan suspicious links before opening them or continue browsing normally.
      </p>

      
      <div className="flex flex-col md:flex-row gap-8 mt-8">
        
     
        <div
          onClick={() => setPage("scan")}
          className="glass-card cursor-pointer w-80 p-6
                     hover:shadow-blue-500/30 hover:scale-[1.02]"
        >
          <h3 className="text-xl font-semibold mb-2">🔍 Scan a URL</h3>
          <p className="text-slate-300 text-sm">
            Paste a website link and check whether it is safe or a phishing attempt.
          </p>
        </div>

      
        <div
          onClick={() => window.open("https://www.google.com", "_blank")}
          className="glass-card cursor-pointer w-80 p-6
                     hover:shadow-cyan-500/30 hover:scale-[1.02]"
        >
          <h3 className="text-xl font-semibold mb-2">🌐 Open New Tab</h3>
          <p className="text-slate-300 text-sm">
            Open a normal browser tab and continue browsing safely.
          </p>
        </div>

      </div>
    </div>
  );
}
