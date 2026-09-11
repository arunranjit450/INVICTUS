"use client";

import { useState } from "react";
import Link from "next/link";

interface SecurityModule {
  name: string;
  status: string;
  statusColor: string;
  category: string;
  description: string;
  engine: string;
  icon: string;
}

const CONFIG_MODULES: SecurityModule[] = [
  {
    name: "Input Guard",
    status: "Active",
    statusColor: "text-emerald-400 bg-emerald-950/60 border-emerald-600/70",
    category: "Pre-Inference Inspection",
    description: "Deterministic regex and pattern matching engine detecting prompt injection, system prompt extraction, confidential data exfiltration, and safety bypasses.",
    engine: "Deterministic Rule Engine (regex)",
    icon: "M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z",
  },
  {
    name: "Output Guard",
    status: "Active",
    statusColor: "text-emerald-400 bg-emerald-950/60 border-emerald-600/70",
    category: "Post-Inference DLP",
    description: "Data loss prevention inspects model responses for system prompt exposure, Project Titan architecture leaks, root KEK tokens, and proprietary source code.",
    engine: "Data Leakage Suppression",
    icon: "M15 12a3 3 0 11-6 0 3 3 0 016 0zM2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z",
  },
  {
    name: "Session Guard",
    status: "Active",
    statusColor: "text-emerald-400 bg-emerald-950/60 border-emerald-600/70",
    category: "Stateful Tracking",
    description: "Thread-safe in-memory session threat state accumulator tracking cumulative risk scores (0–100), distinct attack signatures, and blocked incident counts.",
    engine: "In-Memory SessionTracker",
    icon: "M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z",
  },
  {
    name: "Policy Engine",
    status: "Active",
    statusColor: "text-emerald-400 bg-emerald-950/60 border-emerald-600/70",
    category: "Behavioral Enforcement",
    description: "Evaluates accumulated session risk prior to invoking enterprise AI. Enforces autonomous escalation: LOW (Allow), GUARDED (Monitor), HIGH (Intercept), and CRITICAL (Block).",
    engine: "Deterministic Policy Evaluator",
    icon: "M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4",
  },
  {
    name: "Target Model",
    status: "Aegis Sentinel",
    statusColor: "text-cyan-300 bg-cyan-950/60 border-cyan-700/70",
    category: "Downstream AI Service",
    description: "Mock enterprise AI service simulating an internal corporate AI assistant equipped with public, internal, and confidential Project Titan RAG datasets.",
    engine: "MockEnterpriseLLM (demo/mock_llm.py)",
    icon: "M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z",
  },
  {
    name: "Environment",
    status: "Adversarial Lab",
    statusColor: "text-amber-300 bg-amber-950/60 border-amber-700/70",
    category: "Deployment Sandbox",
    description: "Controlled operational environment configured for defensive validation, real-time SOC security telemetry, and live interactive threat inspection.",
    engine: "FastAPI + Next.js Gateway Matrix",
    icon: "M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z",
  },
];

const THREAT_THRESHOLDS = [
  {
    action: "ALLOW",
    range: "0 – 24",
    level: "LOW RISK",
    color: "emerald",
    bg: "bg-emerald-950/30 border-emerald-800/60 text-emerald-300",
    badge: "bg-emerald-950/80 text-emerald-300 border-emerald-600/70",
    desc: "Query passes all security gates without triggering severe patterns. AI model is invoked normally.",
    policy: "Nominal operational processing; standard event auditing.",
  },
  {
    action: "MONITOR",
    range: "25 – 54",
    level: "GUARDED RISK",
    color: "yellow",
    bg: "bg-yellow-950/30 border-yellow-800/60 text-yellow-300",
    badge: "bg-yellow-950/80 text-yellow-300 border-yellow-600/70",
    desc: "Moderate suspicion or sensitive inquiry detected. Query permitted with heightened session monitoring.",
    policy: "Flagged for SOC review; cumulative session threat score updated.",
  },
  {
    action: "INTERCEPT",
    range: "55 – 79",
    level: "HIGH RISK",
    color: "amber",
    bg: "bg-amber-950/30 border-amber-800/60 text-amber-300",
    badge: "bg-amber-950/80 text-amber-300 border-amber-600/70",
    desc: "High threat confidence detected. Output response is scrutinized and redacted if sensitive data is found.",
    policy: "Response filtered; session elevated to high risk tier.",
  },
  {
    action: "BLOCK",
    range: "80 – 100",
    level: "CRITICAL RISK",
    color: "rose",
    bg: "bg-rose-950/30 border-rose-800/60 text-rose-300",
    badge: "bg-rose-950/80 text-rose-300 border-rose-600/70",
    desc: "Direct prompt injection, jailbreak attempt, or confidential exfiltration confirmed. Model is never invoked.",
    policy: "Immediate HTTP 403 pre-inference block; session marked CRITICAL.",
  },
];

export default function SettingsPage() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState<boolean>(false);

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
              active: true,
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
              <span>Policy Status:</span>
              <span className="text-emerald-400 font-semibold">Enforced</span>
            </div>
            <div className="flex items-center justify-between font-mono">
              <span>Security Core:</span>
              <span className="text-slate-300">v1.0.0</span>
            </div>
            <div className="flex items-center justify-between font-mono">
              <span>Ruleset:</span>
              <span className="text-slate-300">Deterministic</span>
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
              <h1 className="text-lg font-bold text-white tracking-tight">Gateway Settings</h1>
              <p className="text-xs text-slate-400 hidden sm:block">
                Runtime security policy and gateway configuration
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {/* Gateway Policy Indicator */}
            <div className="flex items-center gap-2 rounded-full border border-emerald-800/80 bg-emerald-950/60 px-3 py-1 text-xs font-semibold text-emerald-300">
              <span className="relative flex h-2 w-2">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" />
              </span>
              <span>Policy Enforcing</span>
            </div>
          </div>
        </header>

        {/* Main Content View */}
        <main className="flex-1 p-6 space-y-6 max-w-7xl w-full mx-auto">
          {/* Subtitle for mobile screens */}
          <div className="sm:hidden -mt-2">
            <p className="text-xs text-slate-400">
              Runtime security policy and gateway configuration
            </p>
          </div>

          {/* Architecture & Demo Notice Banner */}
          <div className="rounded-xl border border-slate-700/60 bg-gradient-to-r from-slate-900 via-[#0c121f] to-slate-900 p-5 shadow-sm">
            <div className="flex items-start gap-3.5">
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 mt-0.5">
                <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                  />
                </svg>
              </div>
              <div className="space-y-1">
                <h3 className="text-sm font-semibold text-white">
                  Deterministic Defense & Fictional Data Notice
                </h3>
                <p className="text-xs text-slate-300 leading-relaxed max-w-3xl">
                  This demonstration uses deterministic security rules, multi-layer heuristics, in-memory state tracking, and fictional enterprise data (&quot;Aegis Systems&quot; and &quot;Project Titan&quot;). No external AI APIs, proprietary dependencies, or live enterprise credentials are required.
                </p>
              </div>
            </div>
          </div>

          {/* Section 1: Read-only Configuration Cards (6 Cards) */}
          <section className="space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                <svg className="h-4 w-4 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065zM15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                </svg>
                Active Defense & System Topology (6 Modules)
              </h2>
              <span className="text-[11px] font-mono text-slate-500">All Modules Online</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {CONFIG_MODULES.map((mod, idx) => (
                <div
                  key={idx}
                  className="rounded-xl border border-slate-800/80 bg-[#0c121f] p-5 space-y-3 relative overflow-hidden hover:border-slate-700 transition-all shadow-sm"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-center gap-2.5">
                      <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-slate-800/80 text-emerald-400 border border-slate-700/60 shrink-0">
                        <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d={mod.icon} />
                        </svg>
                      </div>
                      <div>
                        <h3 className="text-sm font-bold text-white tracking-tight">{mod.name}</h3>
                        <div className="text-[10px] uppercase font-mono tracking-wider text-slate-400">
                          {mod.category}
                        </div>
                      </div>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold border shrink-0 ${mod.statusColor}`}>
                      {mod.status}
                    </span>
                  </div>

                  <p className="text-xs text-slate-300 leading-relaxed">
                    {mod.description}
                  </p>

                  <div className="pt-2.5 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-400">
                    <span>Engine:</span>
                    <span className="text-slate-300 truncate max-w-[170px]" title={mod.engine}>
                      {mod.engine}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </section>

          {/* Section 2: Threat Thresholds Matrix */}
          <section className="space-y-3 pt-2">
            <div className="flex items-center justify-between">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                <svg className="h-4 w-4 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
                Threat Thresholds & Enforcement Policies
              </h2>
              <span className="text-[11px] font-mono text-slate-500">Deterministic Bands</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {THREAT_THRESHOLDS.map((thresh, idx) => (
                <div
                  key={idx}
                  className={`rounded-xl border p-5 space-y-3 relative overflow-hidden ${thresh.bg}`}
                >
                  <div className="flex items-center justify-between">
                    <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold border ${thresh.badge}`}>
                      {thresh.action}
                    </span>
                    <span className="text-xs font-mono font-bold text-slate-300">
                      Score: {thresh.range}
                    </span>
                  </div>

                  <div>
                    <div className="text-xs font-mono uppercase tracking-wider opacity-80 font-bold">
                      {thresh.level}
                    </div>
                    <p className="mt-1.5 text-xs text-slate-200 leading-relaxed">
                      {thresh.desc}
                    </p>
                  </div>

                  <div className="pt-2 border-t border-slate-700/50 text-[11px] text-slate-300">
                    <span className="font-semibold text-white">Policy: </span>
                    {thresh.policy}
                  </div>
                </div>
              ))}
            </div>
          </section>

          {/* Quick Nav Shortcut to Attack Lab */}
          <div className="rounded-xl border border-slate-800/80 bg-[#0c121f] p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <h4 className="text-sm font-bold text-white">Ready to test these thresholds?</h4>
              <p className="text-xs text-slate-400 mt-0.5">
                Simulate adversarial injection attacks and observe automatic policy escalation in real-time.
              </p>
            </div>
            <Link
              href="/attack-lab"
              className="inline-flex items-center justify-center gap-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2 text-xs font-semibold shadow transition-all shrink-0"
            >
              <span>Launch Attack Lab</span>
              <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 5l7 7m0 0l-7 7m7-7H3" />
              </svg>
            </Link>
          </div>
        </main>
      </div>
    </div>
  );
}
