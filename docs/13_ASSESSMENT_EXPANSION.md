# 13 — Next-Generation Assessment Layer (V2 Expansion)

Transforms VulnaX-Pro from "discovery + correlation" into a **comprehensive attack
surface assessment platform** — without redesigning existing engines. Everything is
**additive**: new engines communicate via the store and typed models, tools go
through adapters, scope is enforced, and every finding carries evidence.

> Authorized assessments only. Active/dual-use validators are **off by default** and
> require an explicit `--active` flag plus in-scope targets.

---

## 1. Updated Architecture

New pipeline stages (existing engines kept, only re-staged):

```
0  asset_discovery
1  asset_validation
2  service_fingerprint · technology_detection
3  deep_crawler
4  javascript_intelligence · api_discovery · authentication_mapping
5  parameter_intelligence            (NEW)
6  assessment_planner                (NEW, technology-aware decision engine)
7  configuration_assessment · cve_intelligence · extended_detectors (NEW)
8  validation_orchestration          (NEW, active validators — gated)
9  vulnerability_correlation
10 finding_correlation               (NEW, V2 grouping)
11 attack_surface_graph
12 risk_scoring
13 attack_path
14 ai_analyst                        (upgraded)
15 reporting                         (upgraded)
```

New shared infrastructure: `core/confidence.py` (multi-stage confidence),
`core/orchestration.py` (AssessmentPlan + ValidationOrchestrator), new models
`Parameter` and `FindingGroup`, new adapter capabilities `XSS_SCAN` / `SQLI_SCAN`.

---

## 2. New Engine Specifications

### ParameterIntelligenceEngine (`engines/parameter_intelligence.py`, stage 5)
- **Inputs:** endpoints (query + forms), JS-discovered URLs, API/OpenAPI/GraphQL params.
- **Outputs:** `Parameter` records + parameter graph (`Relationship param->endpoint`).
- **Function:** aggregates each parameter across sources/locations/methods, classifies
  it (11 categories: authentication, authorization, object_reference, search,
  redirect, template, file_handling, api_control, administrative, filtering,
  pagination), assigns risk + confidence (rises with #sources and #locations), and
  records sample values + usage context.

### AssessmentPlannerEngine (`engines/assessment_planner.py`, stage 6)
- **Inputs:** technologies, auth mapping, parameter inventory, API/JS discovery.
- **Outputs:** an `AssessmentPlan` (`ctx.store._plan`).
- **Function:** technology-aware decisions — maps detected stacks to assessment
  modules (Laravel/WordPress/Spring/Django/GraphQL/…), derives nuclei tags via
  Payload Intelligence, and selects **parameter-prioritized** XSS/SQLi candidate
  URLs. Reduces unnecessary testing.

### ExtendedDetectorEngine (`engines/extended_detectors.py`, stage 7)
Passive, evidence-backed coverage (no injection):
artifacts/config/secret/backup exposure, directory listing, admin & debug
interfaces, information disclosure (stack traces / SQL errors / internal IPs /
debug banners), TLS weaknesses (deprecated protocol, expired/expiring cert),
GraphQL introspection, JWT weak-alg, container/registry/Kubernetes exposure, and
**parameter-based indicators** for open redirect / path traversal / SSTI / IDOR /
SSRF (flagged `needs_review` as candidates for active validation).

### ValidationOrchestrationEngine (`engines/validation_orchestration.py`, stage 8)
Thin wrapper over `ValidationOrchestrator`. Runs **active validators** (dalfox →
XSS, sqlmap → SQLi) only when `assessment.active` is set, against in-scope,
planner-selected targets. Degrades cleanly when binaries are absent.

### FindingCorrelationEngine (`engines/finding_correlation.py`, stage 10)
Groups validated findings into: **Related Groups** (same asset+category),
**Root-Cause Groups** (shared root cause across assets), **Exposure Groups**
(exposure/secret/config per asset), and **Risk Clusters** (high-risk findings).
Emits `FindingGroup` records consumed by AI + reporting.

---

## 3. Adapter Architecture (additions)

New capabilities `XSS_SCAN`, `SQLI_SCAN`, `CONTENT_DISCOVERY` adapters under the
existing unified `ToolAdapter` contract (execution abstraction, normalization to
typed models, evidence, metrics, retries, timeouts, scope via orchestrator):
**Dalfox** (XSS), **SQLMap** (SQLi), **Feroxbuster** + **Dirsearch** (content
discovery). All optional — absent binaries report unavailable and the orchestrator
skips them. Nuclei/Katana adapters already existed.

---

## 4. Validation Orchestration Design

`core/orchestration.py`:
- **AssessmentPlan** — what to run and where (tech modules, nuclei tags, xss/sqli
  targets, content targets, graphql endpoints).
- **ValidationOrchestrator** — scheduling, **scope enforcement** (`_in_scope`
  filters every target), bounded target counts, per-tool timeouts, normalization
  (adapters), evidence (adapters), duplicate reduction (downstream correlation),
  and a gate on `assessment.active`. Provenance (`detected_by`) is stamped per tool.

Flow: `planner -> plan -> orchestrator.run_active(plan) -> adapters -> Findings`.

---

## 5. Parameter Intelligence Design

Inventory + relationships + risk classification + confidence + usage/context
mapping + parameter graph (see engine above). Classification is keyword + substring
based with an ordered rule list (first match wins), so compound names like
`redirect_uri` resolve correctly. Categories drive both the planner (which active
tests to run) and the extended detectors (which indicators to raise).

---

## 6. Correlation Architecture (V2)

Two complementary layers, neither replacing the other:
- **VulnerabilityCorrelationEngine** (existing, stage 9): multi-source evidence →
  validated findings, dedupe, FP filtering.
- **FindingCorrelationEngine** (new, stage 10): groups validated findings into
  related / root-cause / exposure / risk-cluster views for explainability and
  prioritization.

---

## 7. Confidence Scoring Architecture

`core/confidence.py` — `ConfidenceSignals` → `score_confidence()` producing a 0–1
score and one of four bands (**Critical / High / Medium / Low**). Confidence rises
with: more evidence items, more independent sources, fingerprint agreement; falls
with: response inconsistency, conflicting signals. `merge_confidence()` raises
confidence when an independent source corroborates an existing finding. Used by the
extended detectors and available to all engines.

---

## 8. AI Analyst Enhancements

Now consumes the **parameter inventory** and **finding groups / root causes** in
addition to findings, risk, and attack paths. The executive summary cites parameter
counts, correlation-group counts, and leading root causes. Provider-agnostic
(Anthropic / OpenRouter / DeepSeek / Kimi / Gemini) with offline fallback —
structured evidence only, never raw blobs.

---

## 9. Reporting Enhancements

HTML + Markdown reports gained: **Correlation Groups** section (kind, root cause,
member count, risk), **Parameter Inventory** (totals, by-category breakdown, top
risk parameters with sources), finding **confidence** with rationale, evidence
chains, and root-cause mapping. New dashboard counter: *Parameters Catalogued*.

---

## 10. Implementation Roadmap (status)

| Step | Item | Status |
|------|------|--------|
| 1 | Models `Parameter`, `FindingGroup` + store + confidence model | ✅ done |
| 2 | Parameter Intelligence V2 | ✅ done |
| 3 | Assessment Planner (tech-aware) | ✅ done |
| 4 | Extended detectors (passive coverage) | ✅ done |
| 5 | Adapters: dalfox/sqlmap/feroxbuster/dirsearch | ✅ done |
| 6 | Validation Orchestration (gated active) | ✅ done |
| 7 | Finding Correlation V2 | ✅ done |
| 8 | AI analyst + reporting upgrades | ✅ done |
| 9 | Pipeline re-staging + tests | ✅ done (21 engines, 14 tests) |
| 10 | Verified end-to-end (zero engine errors) | ✅ done |

### Follow-ups (future)
- Archived/historical URL + WebSocket parameter sources.
- Active GraphQL field-suggestion / batching abuse checks (gated).
- Per-tech assessment module packs (Laravel/WordPress/Spring deep checks).
- Sourcemap-based JS parameter recovery.
