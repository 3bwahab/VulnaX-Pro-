# VulnaX-Pro — Enterprise Vulnerability Assessment Framework

> **Status:** Design specification (pre-implementation)
> **Execution model:** Single local Python process — `python main.py`
> **Audience:** Senior engineers implementing the framework directly from this spec.

---

## 1. What VulnaX-Pro Is

VulnaX-Pro is a **standalone, single-process Python framework** for authorized
vulnerability assessment and attack-surface analysis. It orchestrates best-in-class
open-source security tools behind a unified engine architecture, normalizes their
output into a single typed data model, correlates evidence across sources, scores
risk, reconstructs attack paths, and produces commercial-grade reports.

It is intended as a flagship graduation project and a commercial foundation.

## 2. What VulnaX-Pro Is NOT

| Not a... | Consequence for design |
|----------|------------------------|
| SaaS / cloud platform | No tenancy, no remote API, no auth server |
| Web application | No HTTP server, no browser frontend |
| Microservice system | No service mesh, no inter-process RPC |
| Kubernetes / cluster app | No orchestrator, no container runtime dependency |
| Database-server app | Persistence is embedded (SQLite + files), no Postgres/MySQL server |

Everything runs inside **one Python process** launched with `python main.py`.

## 3. Design Pillars

1. **Engine independence** — every engine is a self-contained, reusable unit with a
   declared contract (inputs, outputs, dependencies). Engines never import each
   other directly; they communicate through the shared data model and the pipeline
   bus.
2. **Tool abstraction** — external tools (subfinder, naabu, httpx, katana, nuclei…)
   are reached only through adapters that normalize output into typed models. No
   engine ever parses raw tool stdout.
3. **Asyncio-first concurrency** — the entire pipeline is asynchronous with bounded
   worker pools, rate limits, retries, and timeouts.
4. **Evidence-driven findings** — no finding exists without structured evidence,
   confidence, and references. This is what makes findings explainable and
   AI-consumable.
5. **Professional UX** — the user sees a curated enterprise dashboard, never raw
   `Running subfinder...` noise.
6. **Intelligent payload selection** — VulnaX-Pro never *generates* payloads; it
   *selects* optimal existing resources (SecLists, Nuclei templates) based on
   detected technology.

## 4. The 15 Optimization Targets

Asset Discovery · Attack Surface Visibility · Service Discovery · Technology
Identification · JavaScript Intelligence · API Discovery · Configuration
Assessment · Vulnerability Correlation · Risk Prioritization · Attack Path
Analysis · Evidence Collection · Explainable Findings · Reporting Quality · User
Experience · Execution Speed.

Every architectural decision in this spec is justified against one or more of these.

## 5. The Four Operating Priorities

```
Fast discovery  →  Fast validation  →  Fast correlation
                         ↓
            Low false positives + Professional presentation
```

## 6. Document Map (the 16 Deliverables)

| # | Deliverable | Document |
|---|-------------|----------|
| 1 | Directory structure | `01_DIRECTORY_STRUCTURE.md` |
| 2 | Architecture specification | `02_ARCHITECTURE.md` |
| 3 | Engine-by-engine design | `03_ENGINES.md` |
| 4 | Integration architecture | `04_INTEGRATIONS.md` |
| 5 | CLI architecture | `05_CLI.md` |
| 6 | Data models | `06_DATA_MODELS.md` |
| 7 | Result schemas | `06_DATA_MODELS.md` (§Schemas) |
| 8 | Payload intelligence architecture | `07_PAYLOAD_INTELLIGENCE.md` |
| 9 | Reporting architecture | `08_REPORTING.md` |
| 10 | Attack path architecture | `09_ATTACK_PATH.md` |
| 11 | Mermaid diagrams | `10_DIAGRAMS.md` |
| 12 | Execution flow diagrams | `10_DIAGRAMS.md` (§Execution Flows) |
| 13 | Plugin architecture | `11_PLUGINS.md` |
| 14 | Scaling strategy | `12_SCALING_TESTING_ROADMAP.md` (§Scaling) |
| 15 | Testing strategy | `12_SCALING_TESTING_ROADMAP.md` (§Testing) |
| 16 | Development roadmap | `12_SCALING_TESTING_ROADMAP.md` (§Roadmap) |

## 7. Legal / Operating Boundary

VulnaX-Pro is for **authorized** assessment only (bug-bounty scope, owned assets,
pentest engagements with written authorization). The framework enforces a
mandatory scope file and refuses to run engines against out-of-scope targets.
See `02_ARCHITECTURE.md` §Scope Guard.
