# 12 — Scaling, Testing & Roadmap

---

# Part A — Scaling Strategy

Single process, but designed to scale *within* the box and *across* time.

## A.1 Vertical Scaling (in-process)
- **Async everywhere** + bounded worker pools per resource class (DNS/HTTP/process/
  CPU). Concurrency tuned by profile and adaptive AIMD controller.
- **Streaming batch tools** (httpx/dnsx/naabu/katana via stdin) — handle tens of
  thousands of targets without per-target process spawn overhead.
- **Backpressure** via bounded inter-stage queues prevents memory blowups.
- **CPU-bound work** (graph, scoring, JS AST, secret entropy) offloaded to a
  `ProcessPoolExecutor` so it doesn't block the event loop.

## A.2 Data Scaling
- **SQLite (WAL)** as embedded relational store; indexed by asset/host/severity for
  large result sets. Artifacts (raw output, JS, screenshots) on the filesystem,
  referenced by path — DB stays lean.
- **Streaming reads** for reporting (no full in-memory bundle for huge scans).
- **Pagination** in reports and queries.

## A.3 Work Scaling (avoid redoing work)
- **Content-addressed cache** keyed on `tool+args+input` — re-runs and `--resume`
  skip completed units.
- **Deduplication** at every boundary (normalized host/URL keys).
- **Payload Intelligence pre-filtering** — Nuclei/wordlists scoped to detected tech,
  cutting the largest cost centers dramatically.

## A.4 Scaling Across Targets/Time
- **Scan profiles** (quick/standard/deep/stealth) trade depth for speed.
- **Incremental scans** — diff against a previous scan via stable content-hash ids;
  only probe new/changed assets.
- **Scheduled re-scans** — the framework can be invoked by an external scheduler
  (cron/Task Scheduler); state in the embedded store supports incremental runs.

## A.5 Resource Governance
- Global + per-host + per-tool rate limits protect targets and avoid bans.
- Memory guard: large JS/responses streamed, not fully buffered.
- Hard timeouts + circuit breakers stop pathological tools from stalling a scan.

## A.6 Explicit Non-Goals (per spec)
No distributed workers, no message broker, no DB server, no containers/k8s. If
multi-host scale is ever needed, the unit of distribution would be *whole scans*
(one process per scope shard) writing to a shared artifact location — not
intra-process distribution.

---

# Part B — Testing Strategy

## B.1 Test Pyramid
```
        e2e (few)        full scan on a local lab target
   integration (some)    engine + real adapter on recorded/lab data
      unit (many)        models, normalizers, selectors, scoring, graph, correlation
```

## B.2 Unit Tests (`tests/unit/`)
- **Models/schemas:** validation invariants (e.g., Finding requires evidence),
  serialization round-trips, JSON-Schema export.
- **Normalizers:** feed recorded raw tool output (`tests/fixtures/`) → assert exact
  typed models. One fixture per tool, including malformed lines.
- **Selector:** tech profile → expected resource selection + budget caps.
- **Risk/Correlation/Graph/Path:** deterministic inputs → expected scores/paths.
- **Scope guard:** in/out-of-scope predicates, wildcard + CIDR matching.

## B.3 Integration Tests (`tests/integration/`)
- Each engine against its adapter using **recorded fixtures** (offline, fast,
  hermetic) — no live network in CI.
- Adapter contract tests: `healthcheck`, `version`, timeout, retry, kill-on-timeout
  (using a fake slow binary).
- Pipeline DAG: topological ordering, dependency enforcement, degrade-on-missing-tool.

## B.4 End-to-End (`tests/e2e/`, opt-in)
- Run full `python main.py scan` against a **local intentionally-vulnerable lab**
  (e.g., dockerized DVWA/juice-shop/OWASP targets) — gated behind a marker, not in
  default CI. Asserts report generation, finding presence, exit codes.

## B.5 Quality Gates
- `ruff` (lint), `mypy --strict` (types), `pytest` with coverage threshold.
- **Golden reports:** snapshot a known scan's JSON bundle; diff on changes to catch
  regressions in correlation/scoring.
- **False-positive corpus:** known-benign fixtures must produce zero findings (guards
  the low-FP priority).
- **Determinism test:** same input bundle → byte-stable report ordering.

## B.6 Test Infrastructure
- `conftest.py` fixtures: temp store, fake registry with stub adapters, sample
  scopes.
- Stub adapters return canned models → engines testable without any binary.
- Property-based tests (Hypothesis) for URL/host normalization & dedup.

---

# Part C — Development Roadmap

## Phase 0 — Foundations (kernel)
Core models + schemas, store (SQLite+artifacts), config/scope loading, async
scheduler, rate limit, retry, cache, event bus, logging split, base classes
(`Engine`, `ToolAdapter`), process runner. **Exit:** empty pipeline runs, healthcheck
works, tests for kernel pass.

## Phase 1 — Discovery & Validation (vertical slice)
Adapters: subfinder, dnsx, httpx. Engines: AssetDiscovery, AssetValidation. Live
dashboard MVP. **Exit:** `python main.py scan -d example.com` shows real
Discovery/Validation counters + JSON output.

## Phase 2 — Surface
naabu + wappalyzer adapters; ServiceFingerprint + TechnologyDetection engines;
Payload Intelligence catalog + selector. **Exit:** tech profiles drive selection.

## Phase 3 — Content & Intel
katana/feroxbuster/dirsearch adapters; DeepCrawler, JSIntelligence, ApiDiscovery,
AuthMapping. **Exit:** URLs/JS/API/Auth counters populated; secrets extracted.

## Phase 4 — Assessment
nuclei adapter; CVE dataset sync; ConfigAssessment, CVEIntelligence,
VulnerabilityCorrelation (multi-source + FP filtering). **Exit:** validated findings
with evidence + confidence; Nuclei tag pre-filtering active.

## Phase 5 — Synthesis
AttackSurfaceGraph, RiskScoring, AttackPath. **Exit:** graph + ranked risks +
attack-path narratives.

## Phase 6 — Explain & Report
AIAnalyst (Claude, with offline fallback); ReportingEngine (HTML/MD/JSON, all
audiences). **Exit:** full commercial-grade reports; `--compare` diffing.

## Phase 7 — Hardening & Extensibility
Plugin loader + API surface; profiles (quick/deep/stealth); incremental scans;
performance tuning (adaptive concurrency); golden-report + FP-corpus gates;
documentation + packaging. **Exit:** 1.0 — stable plugin API, reproducible builds.

## Phase 8 — Commercial polish (post-1.0)
White-label theming, scan scheduling integration, richer graph visualization,
additional tech profiles & feeds, optional PDF export pipeline, telemetry opt-in.

## Cross-cutting (every phase)
Tests alongside code, `.wolf` memory updates, buglog discipline, schema versioning,
and scope-guard enforcement reviews.
