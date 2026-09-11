"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import Link from "next/link";

interface SessionRecord {
  session_id: string;
  cumulative_score: number;
  request_count: number;
  blocked_count: number;
  risk_level: "LOW" | "GUARDED" | "HIGH" | "CRITICAL" | string;
  last_action: string | null;
  threat_types_seen: string[];
}

export default function SessionsPage() {
  const [sessions, setSessions] = useState<SessionRecord[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [filterRisk, setFilterRisk] = useState<string>("ALL");
  const [searchTerm, setSearchTerm] = useState<string>("");
  const [mobileMenuOpen, setMobileMenuOpen] = useState<boolean>(false);

  const fetchSessions = useCallback(async () => {
    try {
      const res = await fetch("http://127.0.0.1:8000/api/v1/dashboard/sessions", {
        headers: { Accept: "application/json" },
        cache: "no-store",
      });

      if (!res.ok) {
        throw new Error(`HTTP error! status: ${res.status}`);
      }

      const data: SessionRecord[] = await res.json();
      setSessions(Array.isArray(data) ? data : []);
      setError(null);
      setLastUpdated(new Date());
    } catch (err: unknown) {
      const msg =
        err instanceof Error
          ? err.message
          : "Failed to connect to gateway at http://127.0.0.1:8000.";
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSessions();
    const interval = setInterval(fetchSessions, 5000);
    return () => clearInterval(interval);
  }, [fetchSessions]);

  // Derived metrics for summary cards
  const totalSessions = sessions.length;
  const criticalCount = useMemo(
    () => sessions.filter((s) => s.risk_level.toUpperCase() === "CRITICAL").length,
    [sessions]
  );
  const highRiskCount = useMemo(
    () => sessions.filter((s) => s.risk_level.toUpperCase() === "HIGH").length,
    [sessions]
  );
  const guardedCount = useMemo(
    () => sessions.filter((s) => s.risk_level.toUpperCase() === "GUARDED").length,
    [sessions]
  );
  const lowCount = useMemo(
    () => sessions.filter((s) => s.risk_level.toUpperCase() === "LOW").length,
    [sessions]
  );

  // Filtered session list
  const filteredSessions = useMemo(() => {
    return sessions.filter((s) => {
      const matchesRisk =
        filterRisk === "ALL" || s.risk_level.toUpperCase() === filterRisk.toUpperCase();
      const matchesSearch =
        searchTerm.trim() === "" ||
        s.session_id.toLowerCase().includes(searchTerm.toLowerCase().trim()) ||
        s.threat_types_seen.some((t) => t.toLowerCase().includes(searchTerm.toLowerCase().trim()));
      return matchesRisk && matchesSearch;
    });
  }, [sessions, filterRisk, searchTerm]);

  const getRiskBadge = (risk: string) => {
    const r = risk.toUpperCase();
    switch (r) {
      case "CRITICAL":
        return {
          bg: "bg-rose-950/80 text-rose-300 border-rose-600/80 shadow-sm shadow-rose-900/30",
          dot: "bg-rose-500",
          label: "CRITICAL",
        };
      case "HIGH":
        return {
          bg: "bg-amber-950/80 text-amber-300 border-amber-600/80 shadow-sm shadow-amber-900/30",
          dot: "bg-amber-500",
          label: "HIGH",
        };
      case "GUARDED":
        return {
          bg: "bg-yellow-950/80 text-yellow-300 border-yellow-600/80 shadow-sm shadow-yellow-900/30",
          dot: "bg-yellow-400",
          label: "GUARDED",
        };
      case "LOW":
      default:
        return {
          bg: "bg-emerald-950/80 text-emerald-300 border-emerald-600/80 shadow-sm shadow-emerald-900/30",
          dot: "bg-emerald-400",
          label: "LOW",
        };
    }
  };

  const getActionBadge = (action: string | null) => {
    if (!action) return <span className="text-slate-500 font-mono text-xs">—</span>;
    const a = action.toUpperCase();
    let style = "bg-slate-800 text-slate-300 border-slate-700";
    if (a === "BLOCK") style = "bg-rose-950/70 text-rose-300 border-rose-700/60";
    else if (a === "INTERCEPT") style = "bg-amber-950/70 text-amber-300 border-amber-700/60";
    else if (a === "MONITOR") style = "bg-yellow-950/70 text-yellow-300 border-yellow-700/60";
    else if (a === "ALLOW") style = "bg-emerald-950/70 text-emerald-300 border-emerald-700/60";

    return (
      <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${style}`}>
        {a}
      </span>
    );
  };

  return (
    <div className="flex min-h-screen bg-[#090d16] text-slate-100 font-sans antialiased">
      {/* Sidebar Navigation */}
      <aside
        className={`fixed inset-y-0 left-0 z-40 w-64 transform border-r border-slate-800/80 bg-[#0c121f] transition-transform duration-200 ease-in-out md:translate-x-0 ${
          mobileMenuOpen ? "translate-x-0" : "-translate-x-full"
        }`}
      >
        <div className="flex h-16 items-center gap-3 border-b border-slate-800/80 px-6">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
              />
            </svg>
          </div>
          <div>
            <div className="text-base font-bold tracking-tight text-white flex items-center gap-2">
              LLM Tripwire
              <span className="rounded bg-emerald-900/60 px-1.5 py-0.2 text-[10px] font-semibold text-emerald-300 border border-emerald-500/30">
                SOC
              </span>
            </div>
            <div className="text-xs text-slate-400 font-medium">Runtime AI Security</div>
          </div>
        </div>

        {/* Navigation Items */}
        <nav className="mt-6 px-3 space-y-1">
          {[
            {
              id: "overview",
              label: "Overview",
              href: "/",
              icon: "M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z",
            },
            {
              id: "sessions",
              label: "Sessions",
              href: "/sessions",
              active: true,
              icon: "M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z",
            },
            {
              id: "threats",
              label: "Threats",
              icon: "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z",
            },
            {
              id: "attack-lab",
              label: "Attack Lab",
              href: "/attack-lab",
              icon: "M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z",
            },
            {
              id: "settings",
              label: "Settings",
              icon: "M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065zM15 12a3 3 0 11-6 0 3 3 0 016 0z",
            },
          ].map((item) => {
            const isActive = item.active || false;
            const linkClassName = `flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-all ${
              isActive
                ? "bg-emerald-500/15 text-emerald-300 border border-emerald-500/30"
                : "text-slate-400 hover:bg-slate-800/60 hover:text-slate-200"
            }`;
            const iconSvg = (
              <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d={item.icon} />
              </svg>
            );

            if (item.href) {
              return (
                <Link
                  key={item.id}
                  href={item.href}
                  onClick={() => setMobileMenuOpen(false)}
                  className={linkClassName}
                >
                  {iconSvg}
                  {item.label}
                </Link>
              );
            }

            return (
              <button
                key={item.id}
                onClick={() => setMobileMenuOpen(false)}
                className={linkClassName}
              >
                {iconSvg}
                {item.label}
              </button>
            );
          })}
        </nav>

        {/* System Info Footnote */}
        <div className="absolute bottom-6 left-0 right-0 px-6">
          <div className="rounded-lg border border-slate-800/80 bg-slate-900/60 p-3 text-xs text-slate-400 space-y-1.5">
            <div className="flex items-center justify-between font-mono">
              <span>Guard Mode:</span>
              <span className="text-emerald-400 font-semibold">Stateful Tracker</span>
            </div>
            <div className="flex items-center justify-between font-mono">
              <span>Policy Engine:</span>
              <span className="text-slate-300">Active</span>
            </div>
            <div className="flex items-center justify-between font-mono">
              <span>Poll Interval:</span>
              <span className="text-slate-300">5000ms</span>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 md:pl-64 flex flex-col min-h-screen">
        {/* Top Header */}
        <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-slate-800/80 bg-[#090d16]/90 px-6 backdrop-blur">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="p-1 text-slate-400 hover:text-white md:hidden"
              aria-label="Toggle menu"
            >
              <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
              </svg>
            </button>
            <div>
              <h1 className="text-lg font-bold text-white tracking-tight">Session Monitor</h1>
              <p className="text-xs text-slate-400 hidden sm:block">
                Session-level behavioral risk and enforcement state
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {/* Gateway Status Badge */}
            <div
              className={`flex items-center gap-2 rounded-full px-3 py-1 text-xs font-semibold border transition-colors ${
                error
                  ? "bg-rose-950/60 text-rose-300 border-rose-800/80"
                  : "bg-emerald-950/60 text-emerald-300 border-emerald-800/80"
              }`}
            >
              <span className="relative flex h-2 w-2">
                <span
                  className={`absolute inline-flex h-full w-full animate-ping rounded-full opacity-75 ${
                    error ? "bg-rose-400" : "bg-emerald-400"
                  }`}
                />
                <span
                  className={`relative inline-flex h-2 w-2 rounded-full ${
                    error ? "bg-rose-500" : "bg-emerald-500"
                  }`}
                />
              </span>
              <span>{error ? "Gateway Offline" : "Gateway Online"}</span>
            </div>

            {/* Refresh Button */}
            <button
              onClick={fetchSessions}
              disabled={loading}
              className="flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900/80 px-3 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-800 hover:text-white transition-all disabled:opacity-50"
              title="Refresh session data"
            >
              <svg
                className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`}
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
                />
              </svg>
              <span className="hidden sm:inline">Refresh</span>
            </button>
          </div>
        </header>

        {/* Main Content View */}
        <main className="flex-1 p-6 space-y-6 max-w-7xl w-full mx-auto">
          {/* Subtitle for mobile screens */}
          <div className="sm:hidden -mt-2">
            <p className="text-xs text-slate-400">
              Session-level behavioral risk and enforcement state
            </p>
          </div>

          {/* Backend Unavailable Error Banner */}
          {error && (
            <div className="rounded-xl border border-rose-500/50 bg-rose-950/40 p-4 text-sm text-rose-200 shadow-lg shadow-rose-950/20">
              <div className="flex items-start gap-3">
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-rose-500/20 text-rose-400 border border-rose-500/40">
                  <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                    />
                  </svg>
                </div>
                <div className="flex-1">
                  <h4 className="font-semibold text-rose-200">Gateway Backend Unavailable</h4>
                  <p className="mt-0.5 text-xs text-rose-300/90">{error}</p>
                  <p className="mt-1 text-[11px] text-slate-400">
                    Verify FastAPI is running: <code className="bg-slate-900 px-1 py-0.5 rounded text-slate-300">uvicorn app.main:app --reload --port 8000</code>
                  </p>
                </div>
                <button
                  onClick={fetchSessions}
                  className="rounded bg-rose-900/60 px-2.5 py-1 text-xs font-semibold text-rose-200 hover:bg-rose-800 border border-rose-700/60"
                >
                  Retry
                </button>
              </div>
            </div>
          )}

          {/* 8. Summary Cards: Total Sessions, Critical, High Risk, Guarded */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Card 1: Total Sessions */}
            <div className="rounded-xl border border-slate-800/80 bg-[#0c121f] p-5 relative overflow-hidden group hover:border-slate-700 transition-all">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                  Total Sessions
                </span>
                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-slate-800/60 text-slate-300 border border-slate-700/50">
                  <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"
                    />
                  </svg>
                </div>
              </div>
              <div className="mt-3 flex items-baseline gap-2">
                <span className="text-2xl font-black font-mono text-white tracking-tight">
                  {loading ? "..." : totalSessions}
                </span>
                <span className="text-xs text-slate-400">active states</span>
              </div>
              <div className="mt-2 text-[11px] text-slate-400">
                Tracked in Session Guard memory
              </div>
            </div>

            {/* Card 2: Critical */}
            <div className="rounded-xl border border-rose-900/40 bg-[#0c121f] p-5 relative overflow-hidden group hover:border-rose-700/60 transition-all">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold uppercase tracking-wider text-rose-300">
                  Critical Risk
                </span>
                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-rose-950/80 text-rose-400 border border-rose-800/60">
                  <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                    />
                  </svg>
                </div>
              </div>
              <div className="mt-3 flex items-baseline gap-2">
                <span className="text-2xl font-black font-mono text-rose-400 tracking-tight">
                  {loading ? "..." : criticalCount}
                </span>
                <span className="text-xs text-rose-300/80">score ≥ 75</span>
              </div>
              <div className="mt-2 text-[11px] text-rose-300/70">
                Immediate policy BLOCK enforced
              </div>
            </div>

            {/* Card 3: High Risk */}
            <div className="rounded-xl border border-amber-900/40 bg-[#0c121f] p-5 relative overflow-hidden group hover:border-amber-700/60 transition-all">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold uppercase tracking-wider text-amber-300">
                  High Risk
                </span>
                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-amber-950/80 text-amber-400 border border-amber-800/60">
                  <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                    />
                  </svg>
                </div>
              </div>
              <div className="mt-3 flex items-baseline gap-2">
                <span className="text-2xl font-black font-mono text-amber-400 tracking-tight">
                  {loading ? "..." : highRiskCount}
                </span>
                <span className="text-xs text-amber-300/80">score 50–74</span>
              </div>
              <div className="mt-2 text-[11px] text-amber-300/70">
                INTERCEPT policy active
              </div>
            </div>

            {/* Card 4: Guarded */}
            <div className="rounded-xl border border-yellow-900/40 bg-[#0c121f] p-5 relative overflow-hidden group hover:border-yellow-700/60 transition-all">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold uppercase tracking-wider text-yellow-300">
                  Guarded Risk
                </span>
                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-yellow-950/80 text-yellow-400 border border-yellow-800/60">
                  <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"
                    />
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"
                    />
                  </svg>
                </div>
              </div>
              <div className="mt-3 flex items-baseline gap-2">
                <span className="text-2xl font-black font-mono text-yellow-400 tracking-tight">
                  {loading ? "..." : guardedCount}
                </span>
                <span className="text-xs text-yellow-300/80">score 25–49</span>
              </div>
              <div className="mt-2 text-[11px] text-yellow-300/70">
                MONITOR heightened inspection
              </div>
            </div>
          </div>

          {/* Sessions Table Section */}
          <div className="rounded-xl border border-slate-800/80 bg-[#0c121f] overflow-hidden shadow-sm">
            {/* Filter and Search Bar */}
            <div className="p-4 border-b border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-900/40">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs text-slate-400 font-semibold uppercase tracking-wider mr-1">
                  Filter Risk:
                </span>
                {(["ALL", "CRITICAL", "HIGH", "GUARDED", "LOW"] as const).map((lvl) => {
                  const isActive = filterRisk === lvl;
                  return (
                    <button
                      key={lvl}
                      onClick={() => setFilterRisk(lvl)}
                      className={`px-2.5 py-1 rounded text-xs font-mono font-medium transition-all border ${
                        isActive
                          ? "bg-slate-800 text-white border-slate-600 shadow-sm"
                          : "text-slate-400 border-transparent hover:text-slate-200 hover:bg-slate-800/40"
                      }`}
                    >
                      {lvl}
                    </button>
                  );
                })}
              </div>

              <div className="flex items-center gap-3">
                <div className="relative flex-1 sm:w-64">
                  <input
                    type="text"
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    placeholder="Search session ID or threat..."
                    className="w-full rounded-lg border border-slate-800 bg-[#090d16] px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:border-emerald-500/60 focus:outline-none font-mono"
                  />
                  {searchTerm && (
                    <button
                      onClick={() => setSearchTerm("")}
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-xs text-slate-400 hover:text-white"
                    >
                      ✕
                    </button>
                  )}
                </div>

                <Link
                  href="/attack-lab"
                  className="rounded-lg bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/40 px-3 py-1.5 text-xs font-semibold whitespace-nowrap transition-colors"
                  title="Simulate adversarial sessions in the Attack Lab"
                >
                  + Test in Lab
                </Link>
              </div>
            </div>

            {/* Table Content */}
            {loading ? (
              /* Loading State Skeleton */
              <div className="p-6 space-y-3 animate-pulse">
                {[1, 2, 3, 4, 5].map((i) => (
                  <div key={i} className="h-12 rounded-lg bg-slate-800/40" />
                ))}
              </div>
            ) : filteredSessions.length === 0 ? (
              /* Empty State */
              <div className="p-12 text-center flex flex-col items-center justify-center">
                <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-slate-800/50 text-slate-400 border border-slate-700/50 mb-4">
                  <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={1.8}
                      d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"
                    />
                  </svg>
                </div>
                <h3 className="text-sm font-semibold text-slate-300">
                  {totalSessions === 0 ? "No Active Sessions Recorded" : "No Matching Sessions Found"}
                </h3>
                <p className="mt-1 text-xs text-slate-400 max-w-sm leading-relaxed">
                  {totalSessions === 0
                    ? "Sessions are registered in-memory when queries pass through the LLM Tripwire runtime gateway."
                    : "Try adjusting your risk filter or search keywords."}
                </p>
                {totalSessions === 0 && (
                  <div className="mt-4">
                    <Link
                      href="/attack-lab"
                      className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2 text-xs font-semibold shadow transition-all"
                    >
                      Launch Attack Lab to Generate Traffic
                    </Link>
                  </div>
                )}
              </div>
            ) : (
              /* SOC Table Layout */
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-slate-800 bg-slate-900/70 text-slate-400 font-semibold uppercase tracking-wider">
                    <tr>
                      <th className="py-3.5 px-4">Session ID</th>
                      <th className="py-3.5 px-4">Risk Level</th>
                      <th className="py-3.5 px-4">Score</th>
                      <th className="py-3.5 px-4">Requests</th>
                      <th className="py-3.5 px-4">Blocked</th>
                      <th className="py-3.5 px-4">Last Action</th>
                      <th className="py-3.5 px-4">Threat Types</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono">
                    {filteredSessions.map((sess) => {
                      const badge = getRiskBadge(sess.risk_level);
                      return (
                        <tr
                          key={sess.session_id}
                          className="hover:bg-slate-800/30 transition-colors"
                        >
                          {/* Session ID */}
                          <td className="py-3 px-4 font-semibold text-white whitespace-nowrap">
                            <div className="flex items-center gap-2">
                              <span className={`h-2 w-2 rounded-full shrink-0 ${badge.dot}`} />
                              <span>{sess.session_id}</span>
                            </div>
                          </td>

                          {/* Risk Level */}
                          <td className="py-3 px-4 whitespace-nowrap">
                            <span
                              className={`inline-flex items-center gap-1.5 rounded px-2 py-0.5 text-[11px] font-bold border ${badge.bg}`}
                            >
                              <span className={`h-1.5 w-1.5 rounded-full ${badge.dot}`} />
                              {badge.label}
                            </span>
                          </td>

                          {/* Threat Score with mini meter */}
                          <td className="py-3 px-4 whitespace-nowrap">
                            <div className="flex items-center gap-2">
                              <span
                                className={`font-bold ${
                                  sess.cumulative_score >= 75
                                    ? "text-rose-400"
                                    : sess.cumulative_score >= 50
                                    ? "text-amber-400"
                                    : sess.cumulative_score >= 25
                                    ? "text-yellow-400"
                                    : "text-emerald-400"
                                }`}
                              >
                                {sess.cumulative_score}
                              </span>
                              <div className="w-14 bg-slate-800 rounded-full h-1.5 overflow-hidden">
                                <div
                                  className={`h-full rounded-full ${
                                    sess.cumulative_score >= 75
                                      ? "bg-rose-500"
                                      : sess.cumulative_score >= 50
                                      ? "bg-amber-500"
                                      : sess.cumulative_score >= 25
                                      ? "bg-yellow-400"
                                      : "bg-emerald-500"
                                  }`}
                                  style={{
                                    width: `${Math.min(100, Math.max(5, sess.cumulative_score))}%`,
                                  }}
                                />
                              </div>
                            </div>
                          </td>

                          {/* Requests */}
                          <td className="py-3 px-4 text-slate-300 whitespace-nowrap">
                            {sess.request_count}
                          </td>

                          {/* Blocked */}
                          <td className="py-3 px-4 whitespace-nowrap">
                            <span
                              className={
                                sess.blocked_count > 0
                                  ? "font-bold text-rose-400"
                                  : "text-slate-400"
                              }
                            >
                              {sess.blocked_count}
                            </span>
                          </td>

                          {/* Last Action */}
                          <td className="py-3 px-4 whitespace-nowrap">
                            {getActionBadge(sess.last_action)}
                          </td>

                          {/* Threat Types Seen */}
                          <td className="py-3 px-4">
                            {sess.threat_types_seen && sess.threat_types_seen.length > 0 ? (
                              <div className="flex flex-wrap gap-1">
                                {sess.threat_types_seen.map((t, idx) => (
                                  <span
                                    key={idx}
                                    className="rounded border border-slate-700 bg-slate-800/80 px-1.5 py-0.5 text-[10px] text-slate-300 font-sans truncate max-w-[160px]"
                                    title={t}
                                  >
                                    {t}
                                  </span>
                                ))}
                              </div>
                            ) : (
                              <span className="text-slate-500 text-[11px] font-sans italic">
                                None
                              </span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}

            {/* Footer with telemetry update notice */}
            <div className="p-3 border-t border-slate-800/80 bg-slate-900/40 flex items-center justify-between text-[11px] text-slate-400 font-mono">
              <div className="flex items-center gap-2">
                <span className="inline-block h-1.5 w-1.5 rounded-full bg-emerald-400" />
                <span>Auto-refreshing every 5s</span>
              </div>
              <div>
                {lastUpdated ? (
                  <span>Last synced: {lastUpdated.toLocaleTimeString()}</span>
                ) : (
                  <span>Syncing...</span>
                )}
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
