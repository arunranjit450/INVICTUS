# LLM Tripwire

**Defensive Runtime Security Gateway & SOC Defense Matrix for Large Language Models**

LLM Tripwire is a zero-trust, defensive runtime security gateway engineered to inspect, intercept, and mitigate adversarial AI traffic in real time. Positioned directly in front of LLM inference pathways, it protects enterprise AI systems against prompt injection, jailbreaks, system prompt extraction, proprietary source code theft, confidential data exfiltration, and session-level risk escalation. By coupling pre-inference input validation, streaming data loss prevention (DLP), passive honeytoken tripwires, stateful multi-turn risk scoring, and a real-time Security Operations Center (SOC) dashboard, LLM Tripwire delivers end-to-end observability and autonomous threat mitigation for generative AI deployments.

---

## The Problem

Enterprise adoption of Large Language Models has outpaced runtime security controls. Modern LLM-powered applications face critical attack vectors documented in the OWASP Top 10 for LLMs:
- **Prompt Injections & Jailbreaks**: Adversaries bypass system instructions via roleplay, developer mode exploits, and indirect prompt manipulation.
- **Intellectual Property & Source Code Theft**: Malicious actors coerce models into regurgitating internal algorithms, proprietary codebase fragments, and service architectures.
- **Confidential Data & RAG Exfiltration**: Retrieval-Augmented Generation (RAG) pipelines often inject sensitive corporate documents into model context, which untrusted users can extract through targeted prompt queries.
- **Multi-Turn Session Escalation**: Attackers use gradual, low-severity probing across multiple turns to slowly manipulate the model's safety posture without triggering single-request alarms.

Traditional Web Application Firewalls (WAFs) and perimeter network tools operate on HTTP headers and static signatures, making them incapable of parsing natural language semantics. Crucially, relying on the LLM itself to self-police through system prompt instructions is fundamentally insecure—adversaries can override or manipulate internal instructions.

---

## Core Philosophy

> **"Treat the LLM as an untrusted component rather than the security boundary."**

In robust software engineering, applications never trust databases, third-party microservices, or client-side scripts. Similarly, LLM Tripwire decouples AI reasoning from security enforcement. The model is treated as an untrusted processing unit: every inbound query is scrutinized before inference, and every outbound response is inspected and sanitized before leaving the gateway.

---

## System Architecture

LLM Tripwire sits transparently in the inference pipeline between client applications and downstream AI models:

```
[ User Request ]
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│ 1. Input Guard                                              │
│    • Deterministic pattern matching & regex heuristics      │
│    • Prompt injection, jailbreak, & extraction detection    │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Policy Engine                                            │
│    • Risk threshold evaluation: ALLOW / MONITOR / INTERCEPT │
│    • Immediate BLOCK on hostile inbound queries (403)       │
└──────────────────────────────┬──────────────────────────────┘
                               │ (Allowed / Monitored)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. Target Model (Aegis Sentinel / Enterprise AI)            │
│    • Knowledge retrieval & response generation              │
└──────────────────────────────┬──────────────────────────────┘
                               │ Stream / Token Chunks
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. Stream Guard & Output Guard                              │
│    • Incremental token inspection & cross-chunk boundary DLP│
│    • System prompt, source code, & confidential redaction   │
│    • Canary / Honeytoken passive tripwire triggering        │
│    • Immediate stream termination on leak detection         │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. Session Guard                                            │
│    • Thread-safe stateful risk accumulator                  │
│    • Multi-turn threat scoring & risk tiering (LOW-CRITICAL)│
│    • Autonomous session quarantine on threshold breach      │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 6. Persistent Telemetry Engine                              │
│    • SQLite WAL persistent audit log                        │
│    • Signal distribution & incident forensic records        │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 7. SOC Security Dashboard                                   │
│    • Live Overview, Attack Lab, Sessions, Threats, Settings │
│    • Real-time auto-refresh telemetry & incident monitoring │
└─────────────────────────────────────────────────────────────┘
```

---

## Implemented Security Modules

### 1. Input Guard (`backend/app/security/input_guard.py`)
Pre-inference deterministic inspection engine. It evaluates incoming user queries against compiled regex patterns and heuristic signatures for known attack vectors:
- Direct instruction overrides and jailbreak attempts (`"ignore previous instructions"`, developer modes).
- System prompt extraction probes (`"show system instructions"`, `"repeat prompt verbatim"`).
- Confidential data exfiltration keywords targeting internal corporate assets and keys.
- Source code extraction requests attempting to dump internal repositories.
- Outputs an input threat score (0–100), identified threat types, and matched defense signals.

### 2. Output Guard (`backend/app/security/output_guard.py`)
Post-inference Data Loss Prevention (DLP) engine. Inspects the model's generated text before it reaches the client:
- Detects leaked system prompt instructions and internal protocol disclosures.
- Scans for proprietary source code (e.g., internal token vaults, key derivation algorithms).
- Identifies confidential project references, architecture disclosures, and root keys.
- Integrates with the Canary Detector to catch honeytoken exposures.
- If a leak is detected, redacts or blocks the response and assigns a threat score of 100 with `BLOCK` action.

### 3. Policy Engine (`backend/app/security/policy_engine.py`)
Deterministic decision matrix governing request enforcement and session safety thresholds:
- **ALLOW (0–24)**: Clean traffic; passed directly to model execution.
- **MONITOR (25–54)**: Guarded traffic; permitted with heightened telemetry recording.
- **INTERCEPT (55–79)**: High-risk traffic; flagged for remediation or intervention.
- **BLOCK (80–100)**: Critical threat; execution halted immediately, returning HTTP 403.

### 4. Session Guard (`backend/app/security/session_guard.py`)
Stateful, thread-safe session tracking engine. It tracks cumulative risk across multiple interactions in a session:
- Accumulates threat scores over time (`cumulative_score` 0–100).
- Tracks total request counts, blocked incidents, and unique threat signatures observed.
- Classifies session risk levels: `LOW`, `GUARDED`, `HIGH`, and `CRITICAL`.
- Automatically enforces an autonomous session-level `BLOCK` when an attacker attempts low-and-slow multi-turn exploitation.

### 5. Stream Guard (`backend/app/security/stream_guard.py`)
Real-time streaming inspection mechanism designed for token-by-token LLM output pipelines:
- Inspects response chunks incrementally as they are generated.
- Employs a sliding buffer to reliably detect sensitive strings split across token boundaries (e.g., `AEGIS-` in chunk 1 and `TOKEN...` in chunk 2).
- Immediately severs the stream upon detecting sensitive leaks or canary tokens, preventing the client from receiving malicious content.

### 6. Canary / Honeytoken Detection (`backend/app/security/canary_detector.py`)
Passive defensive tripwire mechanism:
- Registers synthetic, high-entropy honeytokens planted inside protected system prompts or RAG context.
- Monitors output streams for exact occurrences of registered markers.
- **Zero-Exposure Architecture**: Raw canary token values are isolated in backend detector memory and are never transmitted to or displayed by the frontend dashboard.
- Upon detection, triggers a `CANARY_EXPOSURE` defense signal with maximum severity (`CRITICAL`), instantly quarantining the response.

### 7. Telemetry & Persistence Engine (`backend/app/security/telemetry.py`)
Persistent security audit store backed by SQLite with Write-Ahead Logging (WAL):
- Records structured telemetry events: `session_id`, `timestamp`, `attack_type`, `severity`, `threat_score`, `enforcement_action`, `matched_signals`, and `cumulative_session_score`.
- Persists audit logs across backend restarts without external database dependencies.
- Serves aggregated analytics, threat distributions, and canary status to the dashboard APIs.

### 8. SOC Security Dashboard (`frontend/src/app/`)
Modern, dark-themed SOC operations console built with Next.js and Tailwind CSS:
- **Overview (`/`)**: Gateway status, 6-guard defense matrix, live Honeytoken tripwire status, threat distribution charts, and session risk tiering.
- **Attack Lab (`/attack-lab`)**: Interactive red-team workbench with one-click attack presets, live telemetry inspection, and layered decision visualizers.
- **Sessions (`/sessions`)**: Comprehensive session registry showing cumulative threat scores, risk classifications, and quarantine statuses.
- **Threats (`/threats`)**: Real-time incident response feed detailing detected attack patterns, timestamps, and enforcement actions.
- **Settings (`/settings`)**: Runtime gateway configuration, inspection engine status, and policy threshold specifications.

---

## Demonstrated Attack Scenarios

| Attack Scenario | Threat Vector | Gateway Defense Mechanism | Result |
| :--- | :--- | :--- | :--- |
| **Prompt Injection** | Jailbreak & instruction override attempt | Input Guard regex inspection | Blocked at input (HTTP 403); model never invoked |
| **System Prompt Extraction** | Requesting internal prompt verbatim | Input Guard extraction signatures | Blocked at input; prevents prompt exfiltration |
| **Benign Prompt → Output Leak** | Query bypasses input filters, model leaks RAG data | Output Guard post-inference DLP | Input allowed, output blocked & redacted |
| **Source Code Extraction** | Attempt to exfiltrate proprietary cryptographic code | Output Guard source code DLP | Code blocked & suppressed; DLP signal logged |
| **Confidential Data Exfiltration** | Exfiltrating classified project keys | Output Guard data boundary inspection | Intercepted & quarantined; severity marked CRITICAL |
| **Canary / Honeytoken Probe** | Model outputs planted canary marker | Stream Guard + Canary Detector | Stream severed mid-flight; canary alert triggered |
| **Session Risk Escalation** | Multi-turn probing with low-scoring queries | Session Guard cumulative tracking | Risk accumulates until session policy enforces BLOCK |
| **Split-Chunk Streaming Leakage** | Sensitive data split across token fragments | Stream Guard sliding buffer | Detected across chunk boundaries; stream terminated |

---

## Controlled Mock LLM Environment

The repository includes a dedicated simulation environment located in [`demo/mock_llm.py`](demo/mock_llm.py) ("Aegis Sentinel"):
- Simulates an enterprise corporate AI with access to public, internal, and confidential datasets.
- **Intentionally Vulnerable**: The mock LLM is intentionally designed to fulfill adversarial prompts if they reach it. This ensures that the defensive efficacy of LLM Tripwire's guards can be demonstrated deterministically and safely during evaluations without external API costs, latency fluctuations, or non-deterministic model outputs.

---

## Technology Stack

The project relies strictly on lightweight, standard dependencies without unnecessary overhead:

### Backend
- **Language**: Python 3.10+ (tested on Python 3.13)
- **Framework**: FastAPI `>=0.110.0`
- **Server**: Uvicorn `>=0.28.0`
- **Storage**: SQLite with Write-Ahead Logging (standard library `sqlite3`)
- **Testing**: Pytest `>=8.0.0`, HTTPX `>=0.27.0`

### Frontend
- **Framework**: Next.js `16.3.5` (App Router, Turbopack)
- **Library**: React `19.2.8`
- **Language**: TypeScript `5`
- **Styling**: Tailwind CSS `4`, PostCSS
- **Linting**: ESLint `9`

---

## Repository Structure

```
llm-tripwire/
├── README.md                           # Project documentation & architecture
├── .gitignore                          # Git ignore rules
│
├── backend/                            # FastAPI security gateway
│   ├── requirements.txt                # Python dependencies
│   ├── app/
│   │   ├── main.py                     # Application entrypoint & CORS setup
│   │   ├── api/                        # REST API routers
│   │   │   ├── chat.py                 # Core chat inspection endpoint
│   │   │   ├── dashboard.py            # SOC dashboard telemetry endpoints
│   │   │   └── health.py               # Liveness & readiness probes
│   │   ├── security/                   # Core security enforcement modules
│   │   │   ├── input_guard.py          # Pre-inference input inspection
│   │   │   ├── output_guard.py         # Post-inference DLP inspection
│   │   │   ├── policy_engine.py        # Risk scoring & threshold evaluation
│   │   │   ├── session_guard.py        # Multi-turn stateful session risk
│   │   │   ├── stream_guard.py         # Incremental stream inspection
│   │   │   ├── canary_detector.py      # Honeytoken & canary tripwires
│   │   │   └── telemetry.py            # SQLite persistent event store
│   │   └── services/
│   │       └── llm_service.py          # Model dispatch service
│   └── tests/                          # Automated backend test suite (100 tests)
│       ├── test_canary_detector.py
│       ├── test_chat.py
│       ├── test_dashboard.py
│       ├── test_health.py
│       ├── test_input_guard.py
│       ├── test_output_guard.py
│       ├── test_policy_engine.py
│       ├── test_session_guard.py
│       ├── test_stream_guard.py
│       └── test_telemetry.py
│
├── demo/                               # Controlled demonstration environment
│   ├── mock_llm.py                     # Intentionally vulnerable enterprise AI mock
│   └── data/                           # Simulated enterprise knowledge base
│       ├── public/                     # Public corporate information
│       ├── internal/                   # Internal employee guidelines
│       └── confidential/               # Restricted project data & keys
│
└── frontend/                           # Next.js SOC operations dashboard
    ├── package.json                    # Node dependencies & build scripts
    ├── tsconfig.json                   # TypeScript configuration
    └── src/
        └── app/
            ├── page.tsx                # Security Overview dashboard
            ├── attack-lab/page.tsx     # Interactive Attack Lab workbench
            ├── sessions/page.tsx       # Session threat management
            ├── threats/page.tsx        # Incident intelligence feed
            └── settings/page.tsx       # Gateway configuration & policy rules
```

---

## Installation & Local Setup

### Prerequisites
- **Python**: 3.10 or higher
- **Node.js**: 18.x or higher
- **npm**: 9.x or higher

### 1. Backend Setup

```bash
# Navigate to backend directory
cd backend

# Create and activate a virtual environment
# Windows:
python -m venv venv
venv\Scripts\activate
# Linux/macOS:
# python3 -m venv venv
# source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start the FastAPI gateway server
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

The backend gateway will be operational at `http://127.0.0.1:8000`. Interactive API documentation is available at `http://127.0.0.1:8000/docs`.

### 2. Frontend Setup

```bash
# In a new terminal, navigate to frontend directory
cd frontend

# Install dependencies
npm install

# Start the development server
npm run dev
```

Open `http://localhost:3000` in your browser to access the LLM Tripwire SOC Dashboard.

---

## Verification & Testing

### Backend Test Suite
The backend features an automated Pytest suite covering unit tests, integration paths, stream boundary edge cases, and telemetry persistence:

```bash
cd backend
python -m pytest
```

**Current Test Results:**
```
============================== test session starts ==============================
platform win32 -- Python 3.13.14, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\USER\OneDrive\Desktop\llm-tripwire\backend
plugins: anyio-4.15.1
collected 100 items

tests\test_canary_detector.py ...........                                [ 11%]
tests\test_chat.py ...............                                       [ 26%]
tests\test_dashboard.py ..............                                   [ 40%]
tests\test_health.py .                                                   [ 41%]
tests\test_input_guard.py ........                                       [ 49%]
tests\test_output_guard.py ............                                  [ 61%]
tests\test_policy_engine.py .....                                        [ 66%]
tests\test_session_guard.py ........                                     [ 74%]
tests\test_stream_guard.py .............                                 [ 87%]
tests\test_telemetry.py .............                                    [100%]

======================= 100 passed, 2 warnings in 3.39s =======================
```
*Status: 100 tests passing across 10 test modules (100% pass rate).*

### Frontend Production Build
To verify type safety and compilation:

```bash
cd frontend
npm run build
```

*Status: Compiled successfully with zero TypeScript or linting errors.*

---

## Comparison: OPFOR vs. LLM Tripwire

In cybersecurity evaluations, teams frequently confuse offensive testing frameworks with defensive runtime guards:

| Dimension | OPFOR (Red-Teaming / Evaluation) | LLM Tripwire (Defensive Runtime Gateway) |
| :--- | :--- | :--- |
| **Operational Role** | Offline adversarial testing & benchmarking | In-line runtime protection & active traffic interception |
| **Timing** | Pre-deployment or scheduled pentesting | Real-time (during live user inference) |
| **Primary Objective** | Find flaws, generate jailbreaks, probe model boundaries | Block hostile queries, redact leaks, sever compromised streams |
| **State Tracking** | Static prompt scoring / benchmark metrics | Stateful multi-turn session tracking & risk escalation |
| **SOC Integration** | Generates vulnerability reports | Real-time telemetry, live incident feeds, & active quarantining |
| **Complementary Value** | Identifies weaknesses that need protection | Enforces protection against discovered attack vectors |

---

## Current Prototype Limitations

- **Deterministic Rule-Based Detection**: Current inspection relies on compiled regex patterns and curated heuristic signatures. Complex semantic circumventions that avoid known keyword patterns may require semantic embedding evaluation.
- **Mock LLM Target**: Designed and tested using the simulated enterprise assistant (`demo/mock_llm.py`). Live deployment against proprietary foundation models (e.g., GPT-4, Claude, Gemini) requires proxy adaptation.
- **Prototype-Scale Telemetry**: Uses embedded SQLite with WAL mode, optimized for low latency and zero external dependencies on a single node. High-throughput distributed clusters will require dedicated time-series databases.

---

## Future Scope

1. **Live LLM Provider Proxying**: Drop-in reverse proxy support for commercial API providers (OpenAI, Anthropic, Google Vertex AI) and open-weight inference engines (vLLM, Ollama).
2. **Semantic & Embedding-Based Guardrails**: Integration of lightweight semantic embeddings and SLMs (Small Language Models) for intent classification and context-aware evasion detection.
3. **Enterprise SIEM Connectors**: Native log forwarders for Splunk, Datadog, Elastic, and Microsoft Sentinel supporting Common Event Format (CEF) and OpenTelemetry standards.
4. **Role-Based Access Control (RBAC)**: Fine-grained authentication, API key management, and tenant isolation for SOC operators and enterprise teams.
5. **Distributed Telemetry Backend**: Migration to PostgreSQL / TimescaleDB with Redis caching for scalable, horizontally distributed gateway deployments.
6. **Dynamic Policy Studio**: Visual policy editor allowing security analysts to author custom regex rules, adjust thresholds, and configure DLP masks without code deployments.
