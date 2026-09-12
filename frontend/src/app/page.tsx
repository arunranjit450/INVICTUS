"use client";

import { useEffect, useState, useCallback } from "react";
import Link from "next/link";

interface ThreatDistribution {
  prompt_injection: number;
  system_prompt_extraction: number;
  source_code_extraction: number;
  confidential_data_extraction: number;
  other: number;
}

interface CanaryTelemetry {
  status: "ARMED" | "ACTIVE" | string;
  protected_markers: number;
  leaks_detected: number;
  last_detection: string | null;
  severity: "CRITICAL" | "NOMINAL" | string;
}

interface DashboardSummary {
  total_sessions: number;
  active_sessions: number;
  total_requests: number;
  total_blocked: number;
  critical_sessions: number;
  high_risk_sessions: number;
  monitored_sessions: number;
  threat_distribution: ThreatDistribution;
  canary_telemetry?: CanaryTelemetry;
}

export default function SecurityDashboard() {
  const [data, setData] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [activeTab, setActiveTab] = useState<string>("overview");
  const [mobileMenuOpen, setMobileMenuOpen] = useState<boolean>(false);

  const fetchDashboardData = useCallback(async () => {
    try {
      const res = await fetch("http://127.0.0.1:8000/api/dashboard/overview", {
        headers: { Accept: "application/json" },
        cache: "no-store",
      });

      if (!res.ok) {
        throw new Error(`HTTP error! status: ${res.status}`);
      }

      const json: DashboardSummary = await res.json();
      setData(json);
      setError(null);
      setLastUpdated(new Date());
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to fetch dashboard data";
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 5000);
    return () => clearInterval(interval);
  }, [fetchDashboardData]);

  // Derived metrics
  const totalThreats = data
    ? data.threat_distribution.prompt_injection +
      data.threat_distribution.system_prompt_extraction +
      data.threat_distribution.source_code_extraction +
      data.threat_distribution.confidential_data_extraction +
      data.threat_distribution.other
    : 0;

  const lowRiskSessions = data
    ? Math.max(
        0,
        data.total_sessions -
          (data.critical_sessions + data.high_risk_sessions + data.monitored_sessions)
      )
    : 0;

  const isEmpty = data && data.total_sessions === 0 && data.total_requests === 0;

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
            { id: "overview", label: "Overview", href: "/", icon: "M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" },
            { id: "sessions", label: "Sessions", href: "/sessions", icon: "M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" },
            { id: "threats", label: "Threats", href: "/threats", icon: "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" },
            { id: "attack-lab", label: "Attack Lab", href: "/attack-lab", icon: "M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" },
            { id: "settings", label: "Settings", href: "/settings", icon: "M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065zM15 12a3 3 0 11-6 0 3 3 0 016 0z" },
          ].map((item) => {
            const isActive = activeTab === item.id;
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
                  onClick={() => {
                    setActiveTab(item.id);
                    setMobileMenuOpen(false);
                  }}
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
                onClick={() => {
                  setActiveTab(item.id);
                  setMobileMenuOpen(false);
                }}
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
              <span>Engine:</span>
              <span className="text-emerald-400 font-semibold">Tripwire Core</span>
            </div>
            <div className="flex items-center justify-between font-mono">
              <span>Target:</span>
              <span className="text-slate-300">Aegis Sentinel</span>
            </div>
            <div className="flex items-center justify-between font-mono">
              <span>Poll Rate:</span>
              <span className="text-slate-300">5000ms</span>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 md:pl-64 flex flex-col min-h-screen">
        {/* Top App Header */}
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
              <h1 className="text-lg font-bold text-white tracking-tight">Security Overview</h1>
              <p className="text-xs text-slate-400 hidden sm:block">Runtime AI Security Gateway Defense Matrix</p>
            </div>
          </div>

          <div className="flex items-center gap-4">
            {/* Gateway Status Indicator */}
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

            {/* Manual Refresh Button */}
            <button
              onClick={fetchDashboardData}
              disabled={loading}
              className="flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900/80 px-3 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-800 hover:text-white transition-all disabled:opacity-50"
              title="Refresh security metrics"
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

        {/* Dashboard Main View */}
        <main className="flex-1 p-6 space-y-6 max-w-7xl w-full mx-auto">
          {/* Security Status Panel */}
          <div className="relative overflow-hidden rounded-xl border border-emerald-500/30 bg-gradient-to-r from-emerald-950/40 via-slate-900/80 to-slate-900/80 p-6 shadow-lg shadow-emerald-950/20">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="flex items-start gap-4">
                <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                  <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                    />
                  </svg>
                </div>
                <div>
                  <h2 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
                    LLM Tripwire is actively inspecting AI traffic.
                    <span className="text-xs font-normal text-emerald-400 border border-emerald-500/40 rounded px-1.5 py-0.5 bg-emerald-950/40">
                      Enforcing
                    </span>
                  </h2>
                  <p className="mt-1 text-sm text-slate-300 max-w-2xl">
                    Defensive zero-trust inspection protects Aegis Systems against prompt injections, system prompt exfiltration,
                    proprietary code theft, and confidential RAG document leaks in real time.
                  </p>
                </div>
              </div>

              {/* 6 Defense Guard Status Badges */}
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs font-mono shrink-0">
                <div className="rounded border border-emerald-500/30 bg-emerald-950/30 px-3 py-1.5 text-emerald-300 flex items-center justify-between gap-2">
                  <span>Input Guard:</span>
                  <span className="font-bold text-emerald-400">ACTIVE</span>
                </div>
                <div className="rounded border border-emerald-500/30 bg-emerald-950/30 px-3 py-1.5 text-emerald-300 flex items-center justify-between gap-2">
                  <span>Output Guard:</span>
                  <span className="font-bold text-emerald-400">ACTIVE</span>
                </div>
                <div className="rounded border border-emerald-500/30 bg-emerald-950/30 px-3 py-1.5 text-emerald-300 flex items-center justify-between gap-2">
                  <span>Stream Guard:</span>
                  <span className="font-bold text-emerald-400">ACTIVE</span>
                </div>
                <div className={`rounded border px-3 py-1.5 flex items-center justify-between gap-2 ${
                  (data?.canary_telemetry?.leaks_detected ?? 0) > 0
                    ? "border-rose-500/50 bg-rose-950/40 text-rose-300"
                    : "border-emerald-500/30 bg-emerald-950/30 text-emerald-300"
                }`}>
                  <span>Honeytokens:</span>
                  <span className={`font-bold ${
                    (data?.canary_telemetry?.leaks_detected ?? 0) > 0 ? "text-rose-400" : "text-emerald-400"
                  }`}>
                    {data?.canary_telemetry?.status || "ARMED"}
                  </span>
                </div>
                <div className="rounded border border-emerald-500/30 bg-emerald-950/30 px-3 py-1.5 text-emerald-300 flex items-center justify-between gap-2">
                  <span>Session Guard:</span>
                  <span className="font-bold text-emerald-400">ACTIVE</span>
                </div>
                <div className="rounded border border-emerald-500/30 bg-emerald-950/30 px-3 py-1.5 text-emerald-300 flex items-center justify-between gap-2">
                  <span>Policy Engine:</span>
                  <span className="font-bold text-emerald-400">ACTIVE</span>
                </div>
              </div>
            </div>
          </div>

          {/* Backend Unavailable Error State */}
          {error && (
            <div className="rounded-xl border border-rose-800/80 bg-rose-950/30 p-4 text-sm text-rose-200 flex items-start gap-3">
              <svg className="h-5 w-5 text-rose-400 shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                />
              </svg>
              <div className="flex-1">
                <span className="font-semibold text-white">Backend Connection Offline:</span> Unable to reach FastAPI gateway at{" "}
                <code className="rounded bg-rose-950/80 px-1 py-0.5 text-xs text-rose-300 font-mono">
                  http://127.0.0.1:8000/api/dashboard/overview
                </code>
                . Please verify the backend is running with{" "}
                <code className="rounded bg-black/40 px-1.5 py-0.5 text-xs font-mono text-slate-200">
                  python -m uvicorn app.main:app --reload
                </code>
                .
              </div>
              <button
                onClick={fetchDashboardData}
                className="shrink-0 rounded bg-rose-900/60 hover:bg-rose-800 px-3 py-1 text-xs font-semibold text-rose-100 border border-rose-700"
              >
                Retry
              </button>
            </div>
          )}

          {/* Top Metric Cards */}
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {/* Metric 1: Active Sessions */}
            <div className="rounded-xl border border-slate-800/80 bg-slate-900/60 p-5 shadow-sm">
              <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
                <span>Active Sessions</span>
                <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/20">
                  <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"
                    />
                  </svg>
                </div>
              </div>
              <div className="mt-3 text-3xl font-bold tracking-tight text-white">
                {loading ? (
                  <div className="h-8 w-16 animate-pulse rounded bg-slate-800" />
                ) : (
                  data?.active_sessions ?? 0
                )}
              </div>
              <div className="mt-1 text-xs text-slate-400">
                Total tracked in memory: <span className="text-slate-200 font-semibold">{data?.total_sessions ?? 0}</span>
              </div>
            </div>

            {/* Metric 2: Total Requests */}
            <div className="rounded-xl border border-slate-800/80 bg-slate-900/60 p-5 shadow-sm">
              <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
                <span>Total Requests</span>
                <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                  <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M13 10V3L4 14h7v7l9-11h-7z"
                    />
                  </svg>
                </div>
              </div>
              <div className="mt-3 text-3xl font-bold tracking-tight text-white">
                {loading ? (
                  <div className="h-8 w-16 animate-pulse rounded bg-slate-800" />
                ) : (
                  data?.total_requests ?? 0
                )}
              </div>
              <div className="mt-1 text-xs text-slate-400">
                Inspected by Tripwire gateway
              </div>
            </div>

            {/* Metric 3: Blocked Requests */}
            <div className="rounded-xl border border-slate-800/80 bg-slate-900/60 p-5 shadow-sm">
              <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
                <span>Blocked Requests</span>
                <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/20">
                  <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"
                    />
                  </svg>
                </div>
              </div>
              <div className="mt-3 text-3xl font-bold tracking-tight text-rose-400">
                {loading ? (
                  <div className="h-8 w-16 animate-pulse rounded bg-slate-800" />
                ) : (
                  data?.total_blocked ?? 0
                )}
              </div>
              <div className="mt-1 text-xs text-slate-400">
                Blocked at input, output, or policy
              </div>
            </div>

            {/* Metric 4: Critical Sessions */}
            <div className="rounded-xl border border-slate-800/80 bg-slate-900/60 p-5 shadow-sm">
              <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
                <span>Critical Sessions</span>
                <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
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
              <div className="mt-3 text-3xl font-bold tracking-tight text-amber-400">
                {loading ? (
                  <div className="h-8 w-16 animate-pulse rounded bg-slate-800" />
                ) : (
                  data?.critical_sessions ?? 0
                )}
              </div>
              <div className="mt-1 text-xs text-slate-400">
                Policy status: <span className="text-rose-400 font-semibold">Automatic BLOCK</span>
              </div>
            </div>
          </div>

          {/* Honeytoken & Canary Defense System */}
          <div className={`rounded-xl border p-6 shadow-lg transition-all ${
            (data?.canary_telemetry?.leaks_detected ?? 0) > 0
              ? "border-rose-500/60 bg-gradient-to-r from-rose-950/40 via-slate-900/90 to-slate-900/90 shadow-rose-950/30"
              : "border-slate-800/80 bg-gradient-to-r from-amber-950/15 via-slate-900/70 to-slate-900/70 shadow-black/40"
          }`}>
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
              <div className="flex items-center gap-3.5">
                <div className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border ${
                  (data?.canary_telemetry?.leaks_detected ?? 0) > 0
                    ? "bg-rose-500/15 text-rose-400 border-rose-500/40"
                    : "bg-amber-500/10 text-amber-400 border-amber-500/30"
                }`}>
                  <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                  </svg>
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-base font-bold text-white tracking-tight">
                      Canary &amp; Honeytoken Defense
                    </h3>
                    <span className={`rounded-full px-2.5 py-0.5 text-[11px] font-bold border uppercase tracking-wider font-mono ${
                      (data?.canary_telemetry?.leaks_detected ?? 0) > 0
                        ? "bg-rose-950/80 text-rose-300 border-rose-600 animate-pulse"
                        : "bg-emerald-950/60 text-emerald-300 border-emerald-600/60"
                    }`}>
                      {(data?.canary_telemetry?.leaks_detected ?? 0) > 0 ? "LEAK INTERCEPTED" : "SYSTEM ARMED"}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Synthetic tripwires planted in enterprise prompt context to detect unauthorized exfiltration attempts
                  </p>
                </div>
              </div>

              {/* Status indicator pill */}
              <div className="flex items-center gap-2 font-mono text-xs">
                <div className={`flex items-center gap-2 rounded-lg border px-3 py-1.5 ${
                  (data?.canary_telemetry?.leaks_detected ?? 0) > 0
                    ? "border-rose-700 bg-rose-950/60 text-rose-300"
                    : "border-emerald-800/80 bg-emerald-950/40 text-emerald-300"
                }`}>
                  <span className={`h-2 w-2 rounded-full ${
                    (data?.canary_telemetry?.leaks_detected ?? 0) > 0 ? "bg-rose-500 animate-ping" : "bg-emerald-400"
                  }`} />
                  <span>Status: <strong className="font-bold">{data?.canary_telemetry?.status || "ARMED"}</strong></span>
                </div>
              </div>
            </div>

            {/* 4 Security Telemetry Metrics */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-5">
              {/* 1. Canary Status */}
              <div className="rounded-lg border border-slate-800/80 bg-[#090d16]/70 p-3.5">
                <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">
                  Canary Status
                </div>
                <div className={`mt-1 text-xl font-bold font-mono ${
                  (data?.canary_telemetry?.leaks_detected ?? 0) > 0 ? "text-rose-400" : "text-emerald-400"
                }`}>
                  {data?.canary_telemetry?.status || "ARMED"}
                </div>
                <div className="mt-1 text-[11px] text-slate-400">
                  Deterministic Tripwire
                </div>
              </div>

              {/* 2. Protected Markers */}
              <div className="rounded-lg border border-slate-800/80 bg-[#090d16]/70 p-3.5">
                <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">
                  Protected Markers
                </div>
                <div className="mt-1 text-xl font-bold font-mono text-cyan-400">
                  {data?.canary_telemetry?.protected_markers ?? 1} Active
                </div>
                <div className="mt-1 text-[11px] text-slate-400">
                  Zero-Exposure Tokens
                </div>
              </div>

              {/* 3. Leaks Detected */}
              <div className="rounded-lg border border-slate-800/80 bg-[#090d16]/70 p-3.5">
                <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">
                  Leaks Detected
                </div>
                <div className={`mt-1 text-xl font-bold font-mono ${
                  (data?.canary_telemetry?.leaks_detected ?? 0) > 0 ? "text-rose-400" : "text-slate-300"
                }`}>
                  {data?.canary_telemetry?.leaks_detected ?? 0}
                </div>
                <div className="mt-1 text-[11px] text-slate-400">
                  {(data?.canary_telemetry?.leaks_detected ?? 0) > 0 ? "Exposures Quarantined" : "No Exposures"}
                </div>
              </div>

              {/* 4. Severity & Last Detection */}
              <div className="rounded-lg border border-slate-800/80 bg-[#090d16]/70 p-3.5">
                <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">
                  Canary Severity
                </div>
                <div className={`mt-1 text-xl font-bold font-mono ${
                  data?.canary_telemetry?.severity === "CRITICAL"
                    ? "text-rose-400 font-extrabold"
                    : "text-emerald-400"
                }`}>
                  {data?.canary_telemetry?.severity || "NOMINAL"}
                </div>
                <div className="mt-1 text-[11px] text-slate-400 truncate">
                  {data?.canary_telemetry?.last_detection
                    ? `Last: ${new Date(data.canary_telemetry.last_detection).toLocaleTimeString()}`
                    : "Last: None (Clean)"}
                </div>
              </div>
            </div>

            {/* Zero-Exposure Security Guarantee Notice */}
            <div className="mt-4 flex flex-col sm:flex-row items-start sm:items-center justify-between rounded-lg border border-slate-800/60 bg-black/30 px-3.5 py-2.5 text-xs text-slate-400 gap-2">
              <div className="flex items-center gap-2">
                <svg className="h-4 w-4 text-emerald-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
                <span>
                  <strong>Zero-Exposure Architecture:</strong> Honeytoken string values are securely isolated in the backend detector and never sent to or displayed by the frontend.
                </span>
              </div>
              <span className="shrink-0 font-mono text-[11px] text-emerald-400/80">Stream Guard: ACTIVE</span>
            </div>
          </div>

          {/* Empty / Zero State Callout */}
          {isEmpty && !loading && !error && (
            <div className="rounded-xl border border-dashed border-slate-800 bg-slate-900/30 p-8 text-center">
              <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-slate-800 text-slate-400">
                <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <h3 className="mt-4 text-base font-semibold text-white">No security events recorded yet</h3>
              <p className="mt-1 text-sm text-slate-400 max-w-md mx-auto">
                The gateway is clean and ready. Test attack interception using PowerShell or curl against the chat API:
              </p>
              <div className="mt-4 max-w-xl mx-auto rounded-lg bg-black/60 border border-slate-800 p-3 text-left font-mono text-xs text-emerald-400 overflow-x-auto">
                Invoke-RestMethod -Uri &quot;http://127.0.0.1:8000/api/v1/chat&quot; -Method Post -ContentType &quot;application/json&quot; -Body &apos;{JSON.stringify({ query: "What is Aegis Sentinel?" })}&apos;
              </div>
            </div>
          )}

          {/* Threat Distribution & Session Risk Grid */}
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            {/* Section 1: Threat Distribution */}
            <div className="rounded-xl border border-slate-800/80 bg-slate-900/60 p-6 shadow-sm">
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-4">
                <div>
                  <h3 className="text-base font-bold text-white">Threat Distribution</h3>
                  <p className="text-xs text-slate-400">Attack patterns and exfiltration signals detected</p>
                </div>
                <span className="rounded-full bg-slate-800 px-2.5 py-0.5 text-xs font-semibold text-slate-300">
                  {totalThreats} Total Signals
                </span>
              </div>

              <div className="mt-5 space-y-4">
                {[
                  {
                    name: "Prompt Injection",
                    count: data?.threat_distribution.prompt_injection ?? 0,
                    color: "bg-rose-500",
                    border: "border-rose-500/30",
                    textColor: "text-rose-400",
                  },
                  {
                    name: "System Prompt Extraction",
                    count: data?.threat_distribution.system_prompt_extraction ?? 0,
                    color: "bg-amber-500",
                    border: "border-amber-500/30",
                    textColor: "text-amber-400",
                  },
                  {
                    name: "Source Code Extraction",
                    count: data?.threat_distribution.source_code_extraction ?? 0,
                    color: "bg-indigo-500",
                    border: "border-indigo-500/30",
                    textColor: "text-indigo-400",
                  },
                  {
                    name: "Confidential Data Extraction",
                    count: data?.threat_distribution.confidential_data_extraction ?? 0,
                    color: "bg-cyan-500",
                    border: "border-cyan-500/30",
                    textColor: "text-cyan-400",
                  },
                  {
                    name: "Other",
                    count: data?.threat_distribution.other ?? 0,
                    color: "bg-slate-500",
                    border: "border-slate-500/30",
                    textColor: "text-slate-400",
                  },
                ].map((item) => {
                  const percentage = totalThreats > 0 ? Math.round((item.count / totalThreats) * 100) : 0;
                  return (
                    <div key={item.name} className="space-y-1.5">
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-medium text-slate-300">{item.name}</span>
                        <div className="flex items-center gap-2">
                          <span className={`font-mono font-bold ${item.textColor}`}>{item.count}</span>
                          <span className="text-slate-500 text-[11px] font-mono">({percentage}%)</span>
                        </div>
                      </div>
                      <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800">
                        <div
                          className={`h-full ${item.color} transition-all duration-500 ease-out`}
                          style={{ width: `${totalThreats > 0 ? (item.count / totalThreats) * 100 : 0}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Section 2: Session Risk Breakdown */}
            <div className="rounded-xl border border-slate-800/80 bg-slate-900/60 p-6 shadow-sm">
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-4">
                <div>
                  <h3 className="text-base font-bold text-white">Session Risk Levels</h3>
                  <p className="text-xs text-slate-400">Current risk standing across interaction sessions</p>
                </div>
                <span className="rounded-full bg-slate-800 px-2.5 py-0.5 text-xs font-semibold text-slate-300">
                  {data?.total_sessions ?? 0} Sessions
                </span>
              </div>

              <div className="mt-5 space-y-3.5">
                {/* Critical Tier */}
                <div className="flex items-center justify-between rounded-lg border border-rose-900/50 bg-rose-950/20 p-3.5">
                  <div className="flex items-center gap-3">
                    <span className="flex h-3 w-3 rounded-full bg-rose-500" />
                    <div>
                      <div className="text-sm font-semibold text-rose-300">Critical</div>
                      <div className="text-xs text-slate-400">Score 75–100 • Automatic BLOCK policy</div>
                    </div>
                  </div>
                  <div className="text-right">
                    <span className="text-xl font-bold font-mono text-rose-400">
                      {data?.critical_sessions ?? 0}
                    </span>
                    <div className="text-[11px] text-rose-300/70">Quarantined</div>
                  </div>
                </div>

                {/* High Risk Tier */}
                <div className="flex items-center justify-between rounded-lg border border-orange-900/50 bg-orange-950/20 p-3.5">
                  <div className="flex items-center gap-3">
                    <span className="flex h-3 w-3 rounded-full bg-orange-500" />
                    <div>
                      <div className="text-sm font-semibold text-orange-300">High Risk</div>
                      <div className="text-xs text-slate-400">Score 50–74 • INTERCEPT enforcement</div>
                    </div>
                  </div>
                  <div className="text-right">
                    <span className="text-xl font-bold font-mono text-orange-400">
                      {data?.high_risk_sessions ?? 0}
                    </span>
                    <div className="text-[11px] text-orange-300/70">Intercepted</div>
                  </div>
                </div>

                {/* Monitored Tier */}
                <div className="flex items-center justify-between rounded-lg border border-amber-900/50 bg-amber-950/20 p-3.5">
                  <div className="flex items-center gap-3">
                    <span className="flex h-3 w-3 rounded-full bg-amber-500" />
                    <div>
                      <div className="text-sm font-semibold text-amber-300">Monitored</div>
                      <div className="text-xs text-slate-400">Score 25–49 • Audit logging active</div>
                    </div>
                  </div>
                  <div className="text-right">
                    <span className="text-xl font-bold font-mono text-amber-400">
                      {data?.monitored_sessions ?? 0}
                    </span>
                    <div className="text-[11px] text-amber-300/70">Flagged</div>
                  </div>
                </div>

                {/* Low / Normal Tier */}
                <div className="flex items-center justify-between rounded-lg border border-emerald-900/50 bg-emerald-950/20 p-3.5">
                  <div className="flex items-center gap-3">
                    <span className="flex h-3 w-3 rounded-full bg-emerald-500" />
                    <div>
                      <div className="text-sm font-semibold text-emerald-300">Low / Normal</div>
                      <div className="text-xs text-slate-400">Score 0–24 • Clean traffic ALLOWed</div>
                    </div>
                  </div>
                  <div className="text-right">
                    <span className="text-xl font-bold font-mono text-emerald-400">
                      {lowRiskSessions}
                    </span>
                    <div className="text-[11px] text-emerald-300/70">Authorized</div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Footer Metadata */}
          <footer className="pt-4 flex flex-col sm:flex-row items-center justify-between text-xs text-slate-500 border-t border-slate-800/80 gap-2">
            <div>
              LLM Tripwire Security Gateway • Aegis Systems Testbed
            </div>
            <div>
              {lastUpdated ? (
                <span>Auto-refreshed: {lastUpdated.toLocaleTimeString()}</span>
              ) : (
                <span>Connecting to security gateway...</span>
              )}
            </div>
          </footer>
        </main>
      </div>
    </div>
  );
}
