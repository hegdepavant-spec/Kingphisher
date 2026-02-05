import { useState } from "react";
import Header from "./components/Header";
import Home from "./pages/Home";
import Scan from "./pages/Scan";
import Dashboard from "./pages/Dashboard";

function App() {
  const [page, setPage] = useState("home");
  const [history, setHistory] = useState([]);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 text-white">
      <Header setPage={setPage} />

      {page === "home" && <Home setPage={setPage} />}
      {page === "scan" && (
        <Scan history={history} setHistory={setHistory} setPage={setPage} />
     )}
      {page === "dashboard" && <Dashboard history={history} setPage={setPage}  />}
    </div>
  );
}

export default App;
