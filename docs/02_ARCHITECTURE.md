# 02 — Architecture Specification

## 1. Layered Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│  PRESENTATION LAYER                                                     │
│  CLI (Typer) · Live Dashboard (Rich) · Report Renderers (Jinja2)       │
├──────────────────────────────────────────────────────────────────────┤
│  ORCHESTRATION LAYER                                                    │
│  Pipeline (engine DAG) · Scheduler · Bus · ScanContext · Scope Guard   │
├──────────────────────────────────────────────────────────────────────┤
│  ENGINE LAYER  (16 independent engines)                                 │
│  Discovery · Validation · Fingerprint · Tech · Crawl · JS · API ·      │
│  AuthMap · Config · Correlation · CVE · Graph · Risk · Path · AI · Rpt  │
├──────────────────────────────────────────────────────────────────────┤
│  INTELLIGENCE LAYER                                                     │
│  Payload Intelligence · CVE Intelligence · Risk Model · AI Analyst     │
├──────────────────────────────────────────────────────────────────────┤
│  INTEGRATION LAYER                                                      │
│  Tool Adapters (unified) · Process Runner · Normalizers · Registry     │
├──────────────────────────────────────────────────────────────────────┤
│  KERNEL / INFRA LAYER                                                   │
│  Async runtime · Worker pools · Rate limit · Retry · Cache · Metrics   │
├──────────────────────────────────────────────────────────────────────┤
│  PERSISTENCE LAYER (embedded)                                          │
│  SQLite (relational) · Artifact store (files) · Cache (content-addr)   │
└──────────────────────────────────────────────────────────────────────┘
```

**Dependency rule:** dependencies point downward only. Engines depend on the
kernel and the integration layer, never on each other.

## 2. Core Components

### 2.1 Kernel (`core/kernel.py`)
A lightweight application context built once at startup. Holds singletons:
config, store, scheduler, rate limiter, cache, metrics, adapter registry, UX
dashboard. Engines receive these via `ScanContext` (constructor injection — no
global state, testable).

### 2.2 ScanContext (`core/context.py`)
Immutable per-scan object passed to every engine:
```python
@dataclass(frozen=True)
class ScanContext:
    scan_id: str
    scope: Scope                  # in-scope predicate + targets
    config: Config                # merged profile + overrides
    store: Store                  # read/write typed models
    bus: EventBus
    scheduler: Scheduler
    adapters: AdapterRegistry
    payloads: PayloadSelector
    metrics: MetricsSink
    ux: Dashboard
    started_at: datetime
```
The store is the single source of truth; engines read prior results from it and
write their own. This decouples engine ordering from direct data passing.

### 2.3 Pipeline (`core/pipeline.py`)
Engines are arranged as a **DAG of stages**. The pipeline:
- resolves a topological order from declared dependencies,
- runs independent engines concurrently within a stage,
- streams results to the store and bus as they complete,
- supports `--only`, `--skip`, `--resume` (skips stages whose outputs are cached).

```
Stage 0  DISCOVERY        AssetDiscovery
Stage 1  RESOLUTION       AssetValidation (httpx/dnsx)        ← needs Stage 0
Stage 2  SURFACE          ServiceFingerprint ∥ TechDetection ← needs Stage 1
Stage 3  CONTENT          DeepCrawler                         ← needs Stage 2
Stage 4  INTEL            JSIntelligence ∥ ApiDiscovery ∥ AuthMapping
Stage 5  ASSESS           ConfigAssessment ∥ VulnCorrelation ∥ CVEIntel
Stage 6  SYNTHESIS        AttackSurfaceGraph → RiskScoring → AttackPath
Stage 7  EXPLAIN          AIAnalyst
Stage 8  REPORT           Reporting
```
`∥` = concurrent within the stage. Each engine still internally fans out with its
own worker pool.

### 2.4 Event Bus (`core/bus.py`)
In-process async pub/sub. Engines publish progress + result events; the dashboard
and metrics subscribe. Decouples execution from presentation — **this is how the
UX shows curated counters instead of raw tool output.**

Events: `StageStarted`, `AssetFound`, `AssetValidated`, `TechIdentified`,
`UrlCollected`, `JsAnalyzed`, `EndpointFound`, `FindingValidated`,
`PathDiscovered`, `StageCompleted`, `EngineError`.

### 2.5 Scheduler (`core/scheduler.py`)
Adaptive async scheduler over `asyncio`. Provides:
- bounded worker pools per resource class (`dns`, `http`, `process`, `cpu`),
- adaptive concurrency: AIMD controller raises concurrency while latency/error
  stay healthy, backs off on timeouts/429s,
- per-host fairness so one slow host can't starve others.

### 2.6 Persistence (`core/store.py`)
**Embedded only.** SQLite for relational/queryable data (assets, endpoints,
findings, relationships) + a file artifact store for blobs (raw outputs,
screenshots, JS files). Content-addressed cache keys = `sha256(tool+args+input)`
so re-runs skip completed work. WAL mode for concurrent async writers.

## 3. Scope Guard (mandatory)

`core/scope.py` loads `config/scope.yaml` (required — the run aborts without it).
Defines include/exclude rules over domains, IP ranges (CIDR), and ports.

```yaml
scope:
  in_scope:
    domains: ["example.com", "*.example.com"]
    cidrs:   ["203.0.113.0/24"]
  out_of_scope:
    domains: ["status.example.com", "blog.example.com"]
  ports: [80, 443, 8080, 8443]
  rate:  { global_rps: 50, per_host_rps: 10 }
```

Every adapter call passes targets through `scope.is_in_scope(target)`; out-of-scope
targets are dropped and logged. This is enforced at the integration layer so **no
engine can bypass it.**

## 4. Configuration Model

Layered merge (lowest → highest precedence):
`default.yaml` → selected `profiles/<name>.yaml` → `--set key=value` CLI overrides
→ environment (`VULNAX_*`). Validated against `config/schema/` (Pydantic). Secrets
(API keys) come only from `.env` / environment, never committed.

## 5. Concurrency & Performance Model

| Concern | Mechanism |
|---------|-----------|
| Parallelism | asyncio + bounded pools per resource class |
| Tool execution | async subprocess, streamed stdout, hard timeout + kill-tree |
| Rate limiting | token bucket: global + per-host + per-tool |
| Retries | exponential backoff + jitter, circuit breaker per tool |
| Dedup | normalized keys + content-addressed cache |
| Batching | adapters accept target batches (stdin streaming to httpx/dnsx/naabu) |
| Backpressure | bounded queues between pipeline stages |
| Metrics | per-engine timing, throughput, error rate, cache hit ratio |

Tool preference for speed: **Naabu** > nmap, **Httpx** for validation, **Katana**
for crawl, **Dnsx** for resolution — all batch/stream friendly.

## 6. Error Handling Philosophy

- Typed exceptions in `core/errors.py` (`ToolNotFound`, `ToolTimeout`,
  `ScopeViolation`, `AdapterParseError`, `EngineError`).
- Engine failures are **isolated**: a failed engine degrades results, never crashes
  the pipeline. Partial results are always persisted and reported.
- Every error carries context (engine, tool, target, command) for the buglog.

## 7. Observability

Two output planes, strictly separated:
- **UX plane** → curated dashboard (counts, progress, findings) on the console.
- **Diagnostic plane** → structured JSONL logs to `artifacts/<scan_id>/run.log`
  with full tool commands and stack traces. The user never sees raw tool spew on
  the console unless `--verbose/--debug`.

## 8. Extensibility Surfaces

- New tool → drop an adapter implementing `ToolAdapter`, register capability.
- New engine → subclass `Engine`, declare deps, register in pipeline.
- New report → add Jinja2 template + register renderer.
- New tech profile → add `payload_intelligence/profiles/<tech>.yaml`.
- Third-party → `plugins/` (see `11_PLUGINS.md`).
