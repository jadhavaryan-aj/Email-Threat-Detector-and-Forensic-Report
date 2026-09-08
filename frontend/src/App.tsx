import { NavLink, Route, Routes } from "react-router-dom";
import { UploadPage } from "./pages/UploadPage";
import { DashboardPage } from "./pages/DashboardPage";
import { CaseListPage } from "./pages/CaseListPage";
import { CaseDetailPage } from "./pages/CaseDetailPage";

function navClass({ isActive }: { isActive: boolean }) {
  return isActive
    ? "rounded-md bg-zinc-800 px-3 py-1.5 text-sm font-medium text-zinc-100"
    : "rounded-md px-3 py-1.5 text-sm font-medium text-zinc-500 transition hover:text-zinc-200";
}

function App() {
  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      <header className="border-b border-zinc-800 bg-zinc-950/80 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-3">
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-cyan-400" />
            <div>
              <p className="text-sm font-semibold text-zinc-100">SIH26106</p>
              <p className="text-[11px] text-zinc-500">AI Email Threat Detection &amp; Forensic Intelligence Platform</p>
            </div>
          </div>
          <nav className="flex gap-1">
            <NavLink to="/dashboard" className={navClass}>
              Dashboard
            </NavLink>
            <NavLink to="/" end className={navClass}>
              Upload
            </NavLink>
            <NavLink to="/cases" className={navClass}>
              Cases
            </NavLink>
          </nav>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-6 py-8">
        <Routes>
          <Route path="/" element={<UploadPage />} />
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/cases" element={<CaseListPage />} />
          <Route path="/cases/:caseId" element={<CaseDetailPage />} />
        </Routes>
      </main>
    </div>
  );
}

export default App;
