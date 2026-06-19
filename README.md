<div align="center">

# 🐺 VulnaX-Pro

### Enterprise Vulnerability Assessment & Attack-Surface Intelligence Framework

*A standalone, single-process Python platform for **authorized** attack-surface discovery, vulnerability correlation, attack-path reconstruction, and commercial-grade reporting.*

<br/>

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Async](https://img.shields.io/badge/Concurrency-asyncio--first-00B4AB)](https://docs.python.org/3/library/asyncio.html)
[![Architecture](https://img.shields.io/badge/Architecture-Engine%20Pipeline-6E40C9)](docs/02_ARCHITECTURE.md)
[![Reporting](https://img.shields.io/badge/Reports-HTML%20·%20Markdown%20·%20JSON-FF6B35)](docs/08_REPORTING.md)
[![License](https://img.shields.io/badge/Use-Authorized%20Testing%20Only-red)](#-authorization--legal-boundary)
[![Status](https://img.shields.io/badge/Status-v1.0.0-success)](#)

<br/>

```bash
python main.py scan -d example.com --profile standard
```

> 🔒 **Runs entirely locally.** No SaaS. No web app. No microservices. No database server.
> No Docker/Kubernetes requirement. Everything executes inside **one Python process**.

</div>

---

## 📑 Table of Contents

- [Overview](#-overview)
- [Why VulnaX-Pro](#-why-vulnax-pro)
- [Key Features](#-key-features)
- [Architecture at a Glance](#-architecture-at-a-glance)
- [The 16 Core Engines](#-the-16-core-engines)
- [Integrated Tooling](#-integrated-tooling)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Command Reference](#-command-reference)
- [Scope Definition](#-scope-definition)
- [The Live Dashboard](#-the-live-dashboard)
- [Reporting](#-reporting)
- [AI Analyst](#-ai-analyst-optional)
- [Project Layout](#-project-layout)
- [Documentation Library](#-documentation-library)
- [Design Principles](#-design-principles)
- [Authorization & Legal Boundary](#-authorization--legal-boundary)

---

## 🎯 Overview

**VulnaX-Pro** orchestrates best-in-class open-source security tools behind a unified engine
architecture. It normalizes every tool's output into a single typed data model, correlates
evidence across sources, scores risk, reconstructs attack paths, and produces
commercial-grade reports — all from a single command.

Unlike traditional tool wrappers, VulnaX-Pro provides a **unified intelligence pipeline** that
combines asset discovery, service fingerprinting, technology detection, deep crawling,
JavaScript intelligence, API discovery, authentication mapping, vulnerability correlation, CVE
intelligence, attack-path analysis, AI-assisted reasoning, and professional reporting.

It is engineered as both a **flagship engineering project** and a **commercial-grade
foundation**: every architectural decision is justified against measurable optimization targets
(asset discovery depth, false-positive rate, correlation quality, execution speed, and report
fidelity).

```
   Fast discovery  →  Fast validation  →  Fast correlation
                            ↓
            Low false positives  +  Professional presentation
```

---

## 💡 Why VulnaX-Pro

| Most scanners… | VulnaX-Pro… |
|----------------|-------------|
| Dump raw tool output to your terminal | Renders a curated, live **enterprise dashboard** |
| Generate noisy, unverified payloads | **Selects** optimal SecLists/Nuclei resources by detected tech |
| Produce findings without proof | Emits **evidence-driven** findings with confidence + references |
| Treat findings as a flat list | Builds an **attack-surface graph** and reconstructs **attack paths** |
| Require cloud, DB servers, or containers | Runs in **one local Python process** |
| Break when a tool is missing | Falls back to **pure-Python baselines** automatically |

---

## ✨ Key Features

- 🧩 **Engine-independent pipeline** — 16 self-contained engines communicating only through a typed data model and an event bus. No engine imports another.
- 🔌 **Tool abstraction layer** — external tools reached exclusively through normalizing adapters; no engine ever parses raw stdout.
- ⚡ **Asyncio-first concurrency** — bounded worker pools, per-host rate limiting, retries, timeouts, and a cooperative scheduler.
- 🧠 **Payload intelligence** — never generates payloads; intelligently *selects* the right wordlists and Nuclei templates for the detected stack.
- 🕸️ **Attack-surface graph + path analysis** — correlates assets, services, technologies, and findings into exploitable chains.
- 📊 **Risk scoring & correlation** — deduplicates and cross-validates evidence to drive down false positives.
- 🤖 **Multi-provider AI Analyst** — augments findings with explanations and remediation across several providers; gracefully degrades to offline summaries when no API key is present.
- 📄 **Multi-format reporting** — polished HTML, technical Markdown, and machine-readable JSON bundles.
- 🛡️ **Mandatory scope enforcement** — out-of-scope targets are refused at the integration layer.
- 🖥️ **Clean UX / diagnostic separation** — curated console for humans; full JSONL trace plane on disk for debugging and CI.

---

## 🏗️ Architecture at a Glance

```
                          ┌──────────────────────────────┐
                          │           main.py            │
                          │     (Typer CLI · entry)      │
                          └──────────────┬───────────────┘
                                         │
                    ┌────────────────────▼────────────────────┐
                    │                 KERNEL                   │
                    │  store · scheduler · bus · adapters · ux │
                    └────────────────────┬────────────────────┘
                                         │
            ┌────────────────────────────▼────────────────────────────┐
            │                       PIPELINE                           │
            │   Discovery → Validation → Fingerprinting → Crawling →   │
            │   Intel → Correlation → Attack-Path → Reporting          │
            └─────┬───────────────────────────────────────────┬───────┘
                  │                                             │
        ┌─────────▼─────────┐                       ┌───────────▼──────────┐
        │   ENGINES (×16)   │  ── typed models ──▶  │  INTEGRATION ADAPTERS │
        │ independent units │                       │ subfinder/naabu/...   │
        └───────────────────┘                       └──────────────────────┘
                  │                                             │
                  └──────────────┬──────────────────────────────┘
                                 ▼
              ┌──────────────────────────────────────────┐
              │   OUTPUTS: SQLite store · JSON · HTML · MD │
              │   + attack_surface_graph.json + run.log    │
              └──────────────────────────────────────────┘
```

Full details: [`docs/02_ARCHITECTURE.md`](docs/02_ARCHITECTURE.md) · diagrams in [`docs/10_DIAGRAMS.md`](docs/10_DIAGRAMS.md).

---

## ⚙️ The 16 Core Engines

| # | Engine | Responsibility |
|---|--------|----------------|
| 1 | **AssetDiscovery** | Subdomain & asset enumeration across multiple sources |
| 2 | **AssetValidation** | Liveness, resolution, and reachability validation |
| 3 | **ServiceFingerprint** | Port/service identification |
| 4 | **TechnologyDetection** | Stack & framework fingerprinting |
| 5 | **DeepCrawler** | Recursive content & URL collection |
| 6 | **JavaScriptIntelligence** | JS analysis: secrets, endpoints, routes |
| 7 | **ApiDiscovery** | API endpoint & schema discovery |
| 8 | **AuthenticationMapping** | Auth surface & access-control mapping |
| 9 | **ConfigurationAssessment** | Misconfiguration & exposure checks |
| 10 | **VulnerabilityCorrelation** | Cross-source evidence correlation & dedup |
| 11 | **CVEIntelligence** | CVE enrichment for detected tech |
| 12 | **AttackSurfaceGraph** | Graph construction from all entities |
| 13 | **RiskScoring** | Severity & prioritization scoring |
| 14 | **AttackPath** | Exploit-chain reconstruction |
| 15 | **AIAnalyst** | Explanations, triage & remediation (optional) |
| 16 | **Reporting** | HTML / Markdown / JSON generation |

Engine-by-engine design: [`docs/03_ENGINES.md`](docs/03_ENGINES.md).

---

## 🔧 Integrated Tooling

Reached **only** through unified, normalizing adapters:

| Category | Tools |
|----------|-------|
| **Discovery** | `subfinder` · `amass` · `assetfinder` · `findomain` · `chaos` |
| **Validation** | `httpx` · `dnsx` · `naabu` |
| **Crawling** | `katana` |
| **Vulnerability Assessment** | `nuclei` · `dalfox` · `sqlmap` |
| **Content Discovery** | `feroxbuster` · `dirsearch` |
| **Visual Intelligence** | `gowitness` |
| **Technology Detection** | `wappalyzer` |

> Missing tools are **optional** — every engine ships with a pure-Python baseline, so the
> framework runs end-to-end even with no external binaries installed. Run `python main.py doctor`
> to see what's available. Active validators (`dalfox`, `sqlmap`) only run with the `--active`
> flag, against authorized targets.

---

## 📦 Installation

**Requirements:** Python **3.11+**

```bash
# 1. Clone
git clone https://github.com/3bwahab/VulnaX-Pro-.git
cd VulnaX-Pro-

# 2. (Recommended) create a virtual environment
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux / macOS
source .venv/bin/activate

# 3. Install runtime dependencies
pip install -r requirements.txt

# 4. Verify environment & tool availability
python main.py doctor
```

<details>
<summary><b>Runtime dependencies</b></summary>

| Package | Purpose |
|---------|---------|
| `pydantic>=2.0` | Typed data models & validation |
| `httpx>=0.24` | Async HTTP client |
| `rich>=13.0` | Live enterprise dashboard |
| `jinja2>=3.0` | HTML report templating |
| `pyyaml>=6.0` | Scope & config parsing |
| `networkx>=3.0` | Attack-surface graph |
| `dnspython>=2.3` | DNS resolution |
| `typer>=0.9` | CLI framework |
| `beautifulsoup4>=4.11` | HTML/JS parsing |
| `anthropic>=0.30` | AI analyst (optional — offline fallback if absent) |

</details>

---

## 🚀 Quick Start

```bash
# Fastest path: scan a single root domain
python main.py scan -d example.com --profile quick

# Standard assessment from a scope file
python main.py scan --scope config/scope.yaml --profile standard

# Deep scan, only specific engines, AI disabled
python main.py scan -d example.com --profile deep \
    --only AssetDiscovery,TechnologyDetection --no-ai

# Enable active validators (authorized targets only!)
python main.py scan --scope config/scope.yaml --active
```

### Health check example

```text
VulnaX-Pro - Tool Health

┏━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┓
┃ Tool        ┃ Status    ┃ Version          ┃
┡━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━┩
│ subfinder   │ available │ 2.7.1            │
│ httpx       │ available │ 1.7.0            │
│ naabu       │ available │ 2.3.0            │
│ nuclei      │ available │ 3.4.0            │
│ katana      │ available │ 1.1.2            │
└─────────────┴───────────┴──────────────────┘
```

Missing tools are reported but do not prevent execution.

---

## 📟 Command Reference

```
python main.py scan      Run a full assessment pipeline
python main.py doctor    Check tool availability, AI providers & environment
python main.py version   Show framework version
```

### `scan` flags

| Flag | Description |
|------|-------------|
| `-d`, `--domain TEXT` | Quick single-root scope |
| `--scope PATH` | Scope YAML file (required unless `-d`) |
| `--profile {quick,standard,deep,stealth}` | Assessment intensity (default: `standard`) |
| `--only TEXT` | Comma-separated engines to run exclusively |
| `--skip TEXT` | Comma-separated engines to skip |
| `--no-ai` | Disable the AI Analyst engine |
| `--active` | Enable active validators (e.g. `dalfox`/`sqlmap`) — **authorized targets only** |
| `--no-cache` | Ignore cached intermediate results |
| `--debug` | Reveal the diagnostic plane (raw logs) |

**Exit codes:** `0` clean · `2` validated finding ≥ High severity · `1` execution error.

---

## 📋 Scope Definition

A valid scope is **mandatory**. Copy the example and edit it:

```bash
cp config/scope.example.yaml config/scope.yaml
```

```yaml
scope:
  in_scope:
    domains:
      - example.com
      - "*.example.com"
    cidrs: []
  out_of_scope:
    domains:
      - status.example.com
  ports: [80, 443, 8080, 8443, 8000, 8888]
  rate:
    global_rps: 50
    per_host_rps: 10
```

> Out-of-scope targets are refused at the integration layer — the framework will not touch
> anything outside the declared boundary.

---

## 🖥️ The Live Dashboard

VulnaX-Pro renders a curated, Rich-based live view — never raw `Running subfinder...` noise:

```
╔══════════════════════════════════════════════════════════════════════╗
║  VulnaX-Pro   ·   scan 2026-06-15-ab12   ·   scope: *.example.com      ║
╠══════════════════════════════════════════════════════════════════════╣
║  [DISCOVERY]            Assets Found ............... 1,248             ║
║  [VALIDATION]           Live Assets ...............   384             ║
║  [FINGERPRINTING]       Technologies Identified ...   127             ║
║  [CRAWLING]             URLs Collected ............ 14,532             ║
║  [JAVASCRIPT ANALYSIS]  Files Analyzed ............   921             ║
║  [API DISCOVERY]        Endpoints Identified ......  3,241             ║
║  [VULNERABILITY]        Validated Findings ........    18             ║
║  [ATTACK PATHS]         Critical Paths ............     3             ║
╠══════════════════════════════════════════════════════════════════════╣
║  Stage 4/8  INTEL  ▓▓▓▓▓▓▓▓▓▓▓░░░░  68%   elapsed 04:12   eta 01:55    ║
║  Top finding: [CRITICAL] Exposed .git on api.example.com  (conf 0.97)  ║
╚══════════════════════════════════════════════════════════════════════╝
```

In non-TTY/CI environments the dashboard degrades to periodic structured status lines —
still no raw tool spew. Full diagnostic traces stream to `artifacts/<scan_id>/run.log` (JSONL).

---

## 📊 Reporting

Every scan produces a self-contained bundle:

| Output | Location | Description |
|--------|----------|-------------|
| **HTML report** | `reports/<scan_id>/report.html` | Polished, presentation-ready |
| **Technical Markdown** | `reports/<scan_id>/technical.md` | Engineer-focused detail |
| **JSON result** | `output/<scan_id>/result.json` | Machine-readable full result |
| **SQLite store** | `output/<scan_id>/scan.db` | Queryable embedded database |
| **Attack-surface graph** | `artifacts/<scan_id>/attack_surface_graph.json` | Graph entities & edges |
| **Run log** | `artifacts/<scan_id>/run.log` | Full JSONL diagnostic trace |

Reporting design: [`docs/08_REPORTING.md`](docs/08_REPORTING.md).

---

## 🤖 AI Analyst (Optional)

The `AIAnalyst` engine enriches validated findings with explanations, triage, and remediation
guidance. It supports **multiple providers** with automatic fallback, and is **fully optional** —
with no key present, it gracefully degrades to offline summaries.

Configure one or more API keys in a `.env` file at the project root:

```bash
ANTHROPIC_API_KEY=
OPENROUTER_API_KEY=
DEEPSEEK_API_KEY=
KIMI_API_KEY=
GEMINI_API_KEY=
```

Check provider status anytime:

```bash
python main.py doctor
```

```text
AI Providers

┏━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Provider   ┃ Status  ┃ Model                  ┃
┡━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━┩
│ anthropic  │ key set │ claude-opus-4-8        │
│ openrouter │ key set │ deepseek/deepseek-chat │
│ deepseek   │ key set │ deepseek-chat          │
│ kimi       │ key set │ moonshot-v1-8k         │
│ gemini     │ key set │ gemini-1.5-flash       │
└────────────┴─────────┴────────────────────────┘
```

Provider selection automatically falls back when a provider is unavailable.

---

## 🗂️ Project Layout

```
VulnaX-Pro/
├── main.py                  # Single entry point (Typer CLI)
├── requirements.txt
├── core/                    # Kernel: bus, scheduler, pipeline, scope, cache, metrics
├── engines/                 # The 16 independent assessment engines
├── integrations/            # Tool adapters + LLM providers
├── payload_intelligence/    # Resource selection engine + tech profiles
├── utils/                   # HTTP, net, text, version, UX/dashboard
├── config/                  # scope.example.yaml + profiles
├── docs/                    # Full architecture & design library (13 docs)
├── reports/                 # Generated HTML / Markdown reports
├── output/                  # JSON results + SQLite stores
└── artifacts/               # Attack-surface graphs + diagnostic logs
```

Full layout: [`docs/01_DIRECTORY_STRUCTURE.md`](docs/01_DIRECTORY_STRUCTURE.md).

---

## 📚 Documentation Library

| Doc | Covers |
|-----|--------|
| [00_OVERVIEW](docs/00_OVERVIEW.md) | Scope, pillars, optimization targets, doc map |
| [01_DIRECTORY_STRUCTURE](docs/01_DIRECTORY_STRUCTURE.md) | Full on-disk layout |
| [02_ARCHITECTURE](docs/02_ARCHITECTURE.md) | Layers, kernel, pipeline, scope guard |
| [03_ENGINES](docs/03_ENGINES.md) | Engine-by-engine design (all 16) |
| [04_INTEGRATIONS](docs/04_INTEGRATIONS.md) | Tool adapter layer |
| [05_CLI](docs/05_CLI.md) | CLI + live enterprise dashboard UX |
| [06_DATA_MODELS](docs/06_DATA_MODELS.md) | Typed models + result schemas |
| [07_PAYLOAD_INTELLIGENCE](docs/07_PAYLOAD_INTELLIGENCE.md) | Resource selection engine |
| [08_REPORTING](docs/08_REPORTING.md) | Multi-format reporting |
| [09_ATTACK_PATH](docs/09_ATTACK_PATH.md) | Surface graph + attack paths |
| [10_DIAGRAMS](docs/10_DIAGRAMS.md) | Mermaid + execution-flow diagrams |
| [11_PLUGINS](docs/11_PLUGINS.md) | Plugin architecture |
| [12_SCALING_TESTING_ROADMAP](docs/12_SCALING_TESTING_ROADMAP.md) | Scaling, testing, roadmap |

---

## 🧭 Design Principles

1. **Engine independence** — every engine is a self-contained, reusable unit with a declared contract. Engines communicate only via the shared data model and pipeline bus.
2. **Tool abstraction** — external tools are reached only through adapters that normalize output into typed models.
3. **Asyncio-first concurrency** — the entire pipeline is asynchronous with bounded worker pools, rate limits, retries, and timeouts.
4. **Evidence-driven findings** — no finding exists without structured evidence, confidence, and references — making findings explainable and AI-consumable.
5. **Professional UX** — a curated enterprise dashboard, never raw tool noise.
6. **Intelligent payload selection** — never *generates* payloads; *selects* optimal existing resources by detected technology.

---

## 🔐 Authorization & Legal Boundary

> [!WARNING]
> **VulnaX-Pro is for authorized assessment only.**

Permitted use is limited to:

- ✅ Bug-bounty programs **within their declared scope**
- ✅ Assets you **own**
- ✅ Internal security assessments
- ✅ Penetration-testing engagements **with written authorization**

A valid scope file is **mandatory**, and out-of-scope targets are **refused at the integration
layer**. Unauthorized scanning of systems you do not own or lack permission to test is illegal in
most jurisdictions. **You are solely responsible for ensuring you have explicit authorization
before running any scan.**

---

## 📄 License

This project is provided for **educational, research, and authorized security assessment**
purposes. Always obtain proper authorization before testing any target.

---

<div align="center">

**VulnaX-Pro v1.0.0** — Built for serious, authorized security work.

</div>
