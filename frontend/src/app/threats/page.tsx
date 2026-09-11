"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import Link from "next/link";

interface ThreatDistribution {
  prompt_injection: number;
  system_prompt_extraction: number;
  source_code_extraction: number;
  confidential_data_extraction: number;
  other: number;
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
}

interface SessionRecord {
  session_id: string;
  cumulative_score: number;
  request_count: number;
  blocked_count: number;
  risk_level: string;
  last_action: string | null;
  threat_types_seen: string[];
}

interface ThreatEvent {
  id: string;
  timestamp: string;
  session_id: string;
  threat_type: string;
  threat_score: number;
  action: string;
  matched_signal: string;
  risk_level: string;
}

function getCanonicalSignal(threatType: string): string {
  const t = threatType.toLowerCase();
  if (t.includes("prompt_injection")) return "instruction_override_attempt";
  if (t.includes("system_prompt")) return "system_prompt_direct_exfiltration";
  if (t.includes("source_code")) return "proprietary_source_code_exfiltration";
  if (t.includes("confidential")) return "confidential_asset_exfiltration_attempt";
  if (t.includes("safety_bypass")) return "explicit_system_override_keyword";
  if (t.includes("session_policy")) return "session_risk_critical_policy_enforcement";
  return "runtime_threat_pattern_match";
}

export default function ThreatsPage() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [sessions, setSessions] = useState<SessionRecord[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [filterType, setFilterType] = useState<string>("ALL");
  const [searchTerm, setSearchTerm] = useState<string>("");
  const [mobileMenuOpen, setMobileMenuOpen] = useState<boolean>(false);

  const fetchThreatData = useCallback(async () => {
    try {
      const [summaryRes, sessionsRes] = await Promise.all([
        fetch("http://127.0.0.1:8000/api/v1/dashboard/summary", {
          headers: { Accept: "application/json" },
          cache: "no-store",
        }),
        fetch("http://127.0.0.1:8000/api/v1/dashboard/sessions", {
          headers: { Accept: "application/json" },
          cache: "no-store",
        }),
      ]);

      if (!summaryRes.ok || !sessionsRes.ok) {
        throw new Error(`Gateway returned error status (summary: ${summaryRes.status}, sessions: ${sessionsRes.status})`);
      }

      const summaryData: DashboardSummary = await summaryRes.json();
      const sessionsData: SessionRecord[] = await sessionsRes.json();

      setSummary(summaryData);
      setSessions(Array.isArray(sessionsData) ? sessionsData : []);
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
    fetchThreatData();
    const interval = setInterval(fetchThreatData, 5000);
    return () => clearInterval(interval);
  }, [fetchThreatData]);

  // Derived threat metrics
  const totalThreats = useMemo(() => {
    if (!summary) return 0;
    return (
      summary.threat_distribution.prompt_injection +
      summary.threat_distribution.system_prompt_extraction +
      summary.threat_distribution.source_code_extraction +
      summary.threat_distribution.confidential_data_extraction +
      summary.threat_distribution.other
    );
  }, [summary]);

  const blockedThreats = useMemo(() => {
    if (!summary) return 0;
    return summary.total_blocked;
  }, [summary]);

  const criticalThreats = useMemo(() => {
    if (!summary) return 0;
    return summary.critical_sessions;
  }, [summary]);

  const monitoredInterceptedThreats = useMemo(() => {
    if (!summary) return 0;
    return summary.monitored_sessions + summary.high_risk_sessions;
  }, [summary]);

  // Derive granular threat events from in-memory session guard data
  const threatEvents: ThreatEvent[] = useMemo(() => {
    const events: ThreatEvent[] = [];
    const formattedTime = lastUpdated ? lastUpdated.toLocaleTimeString() : "Live Gateway";

    for (const s of sessions) {
      if (s.threat_types_seen && s.threat_types_seen.length > 0) {
        for (const tType of s.threat_types_seen) {
          events.push({
            id: `${s.session_id}-${tType}`,
            timestamp: formattedTime,
            session_id: s.session_id,
            threat_type: tType,
            threat_score: s.cumulative_score,
            action: s.last_action || (s.cumulative_score >= 75 ? "BLOCK" : s.cumulative_score >= 50 ? "INTERCEPT" : "MONITOR"),
            matched_signal: getCanonicalSignal(tType),
            risk_level: s.risk_level,
          });
        }
      } else if (s.blocked_count > 0) {
        events.push({
          id: `${s.session_id}-session-policy-block`,
          timestamp: formattedTime,
          session_id: s.session_id,
          threat_type: "session_policy_block",
          threat_score: s.cumulative_score,
          action: "BLOCK",
          matched_signal: "session_risk_critical_policy_enforcement",
          risk_level: s.risk_level,
        });
      }
    }

    return events;
  }, [sessions, lastUpdated]);

  // Filtered threat events
  const filteredEvents = useMemo(() => {
    return threatEvents.filter((ev) => {
      const matchesType =
        filterType === "ALL" ||
        (filterType === "BLOCKED" && ev.action.toUpperCase() === "BLOCK") ||
        ev.threat_type.toLowerCase().includes(filterType.toLowerCase());

      const matchesSearch =
        searchTerm.trim() === "" ||
        ev.session_id.toLowerCase().includes(searchTerm.toLowerCase().trim()) ||
        ev.threat_type.toLowerCase().includes(searchTerm.toLowerCase().trim()) ||
        ev.matched_signal.toLowerCase().includes(searchTerm.toLowerCase().trim());

      return matchesType && matchesSearch;
    });
  }, [threatEvents, filterType, searchTerm]);

  const getActionBadge = (action: string) => {
    const a = action.toUpperCase();
    let style = "bg-slate-800 text-slate-300 border-slate-700";
    if (a === "BLOCK") style = "bg-rose-950/80 text-rose-300 border-rose-700/80 shadow-sm shadow-rose-950/40";
    else if (a === "INTERCEPT") style = "bg-amber-950/80 text-amber-300 border-amber-700/80";
    else if (a === "MONITOR") style = "bg-yellow-950/80 text-yellow-300 border-yellow-700/80";
    else if (a === "ALLOW") style = "bg-emerald-950/80 text-emerald-300 border-emerald-700/80";

    return (
      <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${style}`}>
        {a}
      </span>
    );
  };

  const getThreatTypeBadge = (tType: string) => {
    const t = tType.toLowerCase();
    let color = "text-rose-300 bg-rose-950/50 border-rose-800/60";
    if (t.includes("prompt_injection")) color = "text-rose-300 bg-rose-950/60 border-rose-700/60";
    else if (t.includes("system_prompt")) color = "text-amber-300 bg-amber-950/60 border-amber-700/60";
    else if (t.includes("confidential")) color = "text-rose-300 bg-rose-950/60 border-rose-700/60";
    else if (t.includes("source_code")) color = "text-yellow-300 bg-yellow-950/60 border-yellow-700/60";

    return (
      <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium border ${color}`}>
        {tType}
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
              icon: "M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z",
            },
            {
              id: "threats",
              label: "Threats",
              href: "/threats",
              active: true,
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
              href: "/settings",
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
              <span>Telemetry:</span>
              <span className="text-emerald-400 font-semibold">Threat Engine</span>
            </div>
            <div className="flex items-center justify-between font-mono">
              <span>Inspection:</span>
              <span className="text-slate-300">Input & Output</span>
            </div>
            <div className="flex items-center justify-between font-mono">
              <span>Sync Rate:</span>
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
              <h1 className="text-lg font-bold text-white tracking-tight">Threat Monitor</h1>
              <p className="text-xs text-slate-400 hidden sm:block">
                Real-time threat detection and security event telemetry
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
              onClick={fetchThreatData}
              disabled={loading}
              className="flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900/80 px-3 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-800 hover:text-white transition-all disabled:opacity-50"
              title="Refresh threat metrics"
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
              Real-time threat detection and security event telemetry
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
                  onClick={fetchThreatData}
                  className="rounded bg-rose-900/60 px-2.5 py-1 text-xs font-semibold text-rose-200 hover:bg-rose-800 border border-rose-700/60"
                >
                  Retry
                </button>
              </div>
            </div>
          )}

          {/* 4 Threat Metric Cards: Total threats, Blocked threats, Critical threats, Monitored/intercepted threats */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Card 1: Total Threats */}
            <div className="rounded-xl border border-slate-800/80 bg-[#0c121f] p-5 relative overflow-hidden group hover:border-slate-700 transition-all">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                  Total Threats
                </span>
                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-slate-800/60 text-slate-300 border border-slate-700/50">
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
                <span className="text-2xl font-black font-mono text-white tracking-tight">
                  {loading ? "..." : totalThreats}
                </span>
                <span className="text-xs text-slate-400">detected signals</span>
              </div>
              <div className="mt-2 text-[11px] text-slate-400">
                Aggregated across all inspect tiers
              </div>
            </div>

            {/* Card 2: Blocked Threats */}
            <div className="rounded-xl border border-rose-900/40 bg-[#0c121f] p-5 relative overflow-hidden group hover:border-rose-700/60 transition-all">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold uppercase tracking-wider text-rose-300">
                  Blocked Threats
                </span>
                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-rose-950/80 text-rose-400 border border-rose-800/60">
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
              <div className="mt-3 flex items-baseline gap-2">
                <span className="text-2xl font-black font-mono text-rose-400 tracking-tight">
                  {loading ? "..." : blockedThreats}
                </span>
                <span className="text-xs text-rose-300/80">enforced blocks</span>
              </div>
              <div className="mt-2 text-[11px] text-rose-300/70">
                Model execution stopped at gateway
              </div>
            </div>

            {/* Card 3: Critical Threats */}
            <div className="rounded-xl border border-rose-900/40 bg-[#0c121f] p-5 relative overflow-hidden group hover:border-rose-700/60 transition-all">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold uppercase tracking-wider text-rose-300">
                  Critical Threats
                </span>
                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-rose-950/80 text-rose-400 border border-rose-800/60">
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
                <span className="text-2xl font-black font-mono text-rose-400 tracking-tight">
                  {loading ? "..." : criticalThreats}
                </span>
                <span className="text-xs text-rose-300/80">score ≥ 75</span>
              </div>
              <div className="mt-2 text-[11px] text-rose-300/70">
                High severity attacks & policy blocks
              </div>
            </div>

            {/* Card 4: Monitored / Intercepted Threats */}
            <div className="rounded-xl border border-amber-900/40 bg-[#0c121f] p-5 relative overflow-hidden group hover:border-amber-700/60 transition-all">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold uppercase tracking-wider text-amber-300">
                  Monitored / Intercepted
                </span>
                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-amber-950/80 text-amber-400 border border-amber-800/60">
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
                <span className="text-2xl font-black font-mono text-amber-400 tracking-tight">
                  {loading ? "..." : monitoredInterceptedThreats}
                </span>
                <span className="text-xs text-amber-300/80">heightened scrutiny</span>
              </div>
              <div className="mt-2 text-[11px] text-amber-300/70">
                Guarded or high risk active sessions
              </div>
            </div>
          </div>

          {/* Threat Distribution Matrix Bar */}
          {summary && (
            <div className="rounded-xl border border-slate-800/80 bg-[#0c121f] p-5">
              <div className="flex items-center justify-between mb-3">
                <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                  <svg className="h-4 w-4 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                  </svg>
                  Threat Category Telemetry
                </h2>
                <span className="text-[11px] text-slate-400 font-mono">
                  {totalThreats} total events
                </span>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
                {[
                  { label: "Prompt Injection", count: summary.threat_distribution.prompt_injection, color: "text-rose-400 bg-rose-950/40 border-rose-800/60" },
                  { label: "System Prompt Extraction", count: summary.threat_distribution.system_prompt_extraction, color: "text-amber-400 bg-amber-950/40 border-amber-800/60" },
                  { label: "Source Code Extraction", count: summary.threat_distribution.source_code_extraction, color: "text-yellow-400 bg-yellow-950/40 border-yellow-800/60" },
                  { label: "Confidential Data", count: summary.threat_distribution.confidential_data_extraction, color: "text-rose-400 bg-rose-950/40 border-rose-800/60" },
                  { label: "Other / Anomaly", count: summary.threat_distribution.other, color: "text-slate-300 bg-slate-800/60 border-slate-700/60" },
                ].map((item, idx) => (
                  <div key={idx} className={`rounded-lg border p-3 ${item.color}`}>
                    <div className="text-[11px] font-medium text-slate-400 truncate">{item.label}</div>
                    <div className="mt-1 text-xl font-black font-mono">{item.count}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Security Event Table Section */}
          <div className="rounded-xl border border-slate-800/80 bg-[#0c121f] overflow-hidden shadow-sm">
            {/* Filter and Search Bar */}
            <div className="p-4 border-b border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-900/40">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs text-slate-400 font-semibold uppercase tracking-wider mr-1">
                  Filter:
                </span>
                {[
                  { id: "ALL", label: "All Events" },
                  { id: "BLOCKED", label: "Blocked" },
                  { id: "prompt_injection", label: "Prompt Injection" },
                  { id: "system_prompt", label: "System Prompt" },
                  { id: "confidential", label: "Confidential" },
                  { id: "source_code", label: "Source Code" },
                ].map((item) => {
                  const isActive = filterType === item.id;
                  return (
                    <button
                      key={item.id}
                      onClick={() => setFilterType(item.id)}
                      className={`px-2.5 py-1 rounded text-xs font-mono font-medium transition-all border ${
                        isActive
                          ? "bg-slate-800 text-white border-slate-600 shadow-sm"
                          : "text-slate-400 border-transparent hover:text-slate-200 hover:bg-slate-800/40"
                      }`}
                    >
                      {item.label}
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
                    placeholder="Search session, threat or signal..."
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
                  title="Test attacks in the Attack Lab"
                >
                  + Simulate in Lab
                </Link>
              </div>
            </div>

            {/* Event Table Content */}
            {loading ? (
              /* Loading State Skeleton */
              <div className="p-6 space-y-3 animate-pulse">
                {[1, 2, 3, 4, 5].map((i) => (
                  <div key={i} className="h-12 rounded-lg bg-slate-800/40" />
                ))}
              </div>
            ) : filteredEvents.length === 0 ? (
              /* Empty State */
              <div className="p-12 text-center flex flex-col items-center justify-center">
                <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-slate-800/50 text-slate-400 border border-slate-700/50 mb-4">
                  <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={1.8}
                      d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                    />
                  </svg>
                </div>
                <h3 className="text-sm font-semibold text-slate-300">
                  {threatEvents.length === 0 ? "No Security Threats Detected" : "No Matching Threat Events Found"}
                </h3>
                <p className="mt-1 text-xs text-slate-400 max-w-sm leading-relaxed">
                  {threatEvents.length === 0
                    ? "All inspected AI gateway traffic is currently nominal. Adversarial prompts generated in the Attack Lab or live chat will populate real-time threat events here."
                    : "Try adjusting your threat category filter or search keywords."}
                </p>
                {threatEvents.length === 0 && (
                  <div className="mt-4">
                    <Link
                      href="/attack-lab"
                      className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2 text-xs font-semibold shadow transition-all"
                    >
                      Launch Attack Lab to Test Threat Defenses
                    </Link>
                  </div>
                )}
              </div>
            ) : (
              /* Security Event Table: Timestamp, Session ID, Threat type, Threat score, Action, Matched defense signal */
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-slate-800 bg-slate-900/70 text-slate-400 font-semibold uppercase tracking-wider">
                    <tr>
                      <th className="py-3.5 px-4">Timestamp</th>
                      <th className="py-3.5 px-4">Session ID</th>
                      <th className="py-3.5 px-4">Threat Type</th>
                      <th className="py-3.5 px-4">Threat Score</th>
                      <th className="py-3.5 px-4">Action</th>
                      <th className="py-3.5 px-4">Matched Defense Signal</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono">
                    {filteredEvents.map((ev) => (
                      <tr
                        key={ev.id}
                        className="hover:bg-slate-800/30 transition-colors"
                      >
                        {/* Timestamp */}
                        <td className="py-3 px-4 text-slate-400 whitespace-nowrap">
                          {ev.timestamp}
                        </td>

                        {/* Session ID */}
                        <td className="py-3 px-4 font-semibold text-white whitespace-nowrap">
                          <Link
                            href="/sessions"
                            className="hover:text-emerald-400 transition-colors"
                            title="Inspect session in Session Monitor"
                          >
                            {ev.session_id}
                          </Link>
                        </td>

                        {/* Threat Type */}
                        <td className="py-3 px-4 whitespace-nowrap">
                          {getThreatTypeBadge(ev.threat_type)}
                        </td>

                        {/* Threat Score */}
                        <td className="py-3 px-4 whitespace-nowrap">
                          <div className="flex items-center gap-2">
                            <span
                              className={`font-bold ${
                                ev.threat_score >= 75
                                  ? "text-rose-400"
                                  : ev.threat_score >= 50
                                  ? "text-amber-400"
                                  : ev.threat_score >= 25
                                  ? "text-yellow-400"
                                  : "text-emerald-400"
                              }`}
                            >
                              {ev.threat_score}
                            </span>
                            <div className="w-12 bg-slate-800 rounded-full h-1.5 overflow-hidden">
                              <div
                                className={`h-full rounded-full ${
                                  ev.threat_score >= 75
                                    ? "bg-rose-500"
                                    : ev.threat_score >= 50
                                    ? "bg-amber-500"
                                    : ev.threat_score >= 25
                                    ? "bg-yellow-400"
                                    : "bg-emerald-500"
                                }`}
                                style={{
                                  width: `${Math.min(100, Math.max(5, ev.threat_score))}%`,
                                }}
                              />
                            </div>
                          </div>
                        </td>

                        {/* Action */}
                        <td className="py-3 px-4 whitespace-nowrap">
                          {getActionBadge(ev.action)}
                        </td>

                        {/* Matched Defense Signal */}
                        <td className="py-3 px-4">
                          <span
                            className="rounded border border-slate-700 bg-slate-800/80 px-2 py-0.5 text-[11px] text-amber-300 font-mono truncate inline-block max-w-[260px]"
                            title={ev.matched_signal}
                          >
                            {ev.matched_signal}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Footer with telemetry update notice */}
            <div className="p-3 border-t border-slate-800/80 bg-slate-900/40 flex items-center justify-between text-[11px] text-slate-400 font-mono">
              <div className="flex items-center gap-2">
                <span className="inline-block h-1.5 w-1.5 rounded-full bg-emerald-400" />
                <span>Threat Telemetry active &bull; Auto-refreshing every 5s</span>
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
