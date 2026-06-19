# 01 — Directory Structure

Complete on-disk layout. Folders marked **(gen)** are created at runtime and
git-ignored.

```
vulnax-pro/
├── main.py                      # Entry point: arg parse → bootstrap → run pipeline
├── pyproject.toml               # Packaging, deps, tool config (ruff/mypy/pytest)
├── requirements.txt             # Pinned runtime deps
├── README.md
├── LICENSE
├── .env.example                 # API keys (Chaos, GitHub, Shodan, LLM) template
│
├── config/
│   ├── default.yaml             # Base config (concurrency, timeouts, rate limits)
│   ├── profiles/                # Scan profiles: quick / standard / deep / stealth
│   │   ├── quick.yaml
│   │   ├── standard.yaml
│   │   └── deep.yaml
│   ├── tools.yaml               # Tool binary paths, version pins, flags
│   ├── scope.example.yaml       # Mandatory scope definition template
│   └── schema/                  # JSON-Schema for config validation
│
├── core/                        # Framework kernel (no security logic here)
│   ├── __init__.py
│   ├── kernel.py                # Application context / service locator
│   ├── pipeline.py              # Stage orchestrator (DAG of engines)
│   ├── bus.py                   # In-process async event/result bus
│   ├── context.py               # ScanContext: shared state, scope, store handle
│   ├── scheduler.py             # Adaptive async scheduler + worker pools
│   ├── ratelimit.py             # Token-bucket per-host / per-tool limiter
│   ├── retry.py                 # Retry policy (backoff, jitter, circuit breaker)
│   ├── cache.py                 # Content-addressed cache (skip repeat work)
│   ├── store.py                 # SQLite + artifact store (the "database", embedded)
│   ├── models.py                # Typed data models (Asset, Endpoint, Finding…)
│   ├── schemas.py               # Pydantic schemas + JSON-Schema export
│   ├── scope.py                 # Scope guard / in-scope predicate
│   ├── metrics.py               # Execution metrics collection
│   ├── errors.py                # Typed exception hierarchy
│   └── logging.py               # Structured logging (file) vs UX (console)
│
├── engines/                     # The 16 core engines (one subpackage each)
│   ├── __init__.py
│   ├── base.py                  # Engine ABC + lifecycle contract
│   ├── asset_discovery/
│   ├── asset_validation/
│   ├── service_fingerprint/
│   ├── technology_detection/
│   ├── deep_crawler/
│   ├── javascript_intelligence/
│   ├── api_discovery/
│   ├── authentication_mapping/
│   ├── configuration_assessment/
│   ├── vulnerability_correlation/
│   ├── cve_intelligence/
│   ├── attack_surface_graph/
│   ├── risk_scoring/
│   ├── attack_path/
│   ├── ai_analyst/
│   └── reporting/
│
├── integrations/                # Tool adapter layer
│   ├── __init__.py
│   ├── base.py                  # ToolAdapter ABC + AdapterResult
│   ├── registry.py              # Adapter discovery + capability map
│   ├── process.py               # Async subprocess runner (stream, timeout, kill)
│   ├── normalizers.py           # Raw → typed model normalizers
│   ├── subfinder.py
│   ├── amass.py
│   ├── assetfinder.py
│   ├── findomain.py
│   ├── chaos.py
│   ├── naabu.py
│   ├── httpx.py
│   ├── dnsx.py
│   ├── katana.py
│   ├── nuclei.py
│   ├── feroxbuster.py
│   ├── dirsearch.py
│   └── wappalyzer.py
│
├── payload_intelligence/        # Resource SELECTION (never generation)
│   ├── __init__.py
│   ├── selector.py              # Tech → optimal wordlist/template selection
│   ├── catalog.py               # Indexed inventory of available resources
│   ├── profiles/                # Tech-specific resource maps (yaml)
│   │   ├── laravel.yaml
│   │   ├── wordpress.yaml
│   │   ├── graphql.yaml
│   │   ├── spa_react.yaml
│   │   └── ...
│   └── rules.yaml               # Selection rules / scoring weights
│
├── wordlists/                   # (gen / vendored) SecLists + curated lists
├── templates/
│   ├── nuclei/                  # (gen) synced Nuclei templates
│   └── report/                  # Jinja2 report templates (html/md)
│       ├── executive.html.j2
│       ├── technical.html.j2
│       ├── asset_inventory.md.j2
│       └── partials/
│
├── reports/                     # (gen) rendered reports per scan
├── output/                      # (gen) normalized JSON result bundles
├── artifacts/                   # (gen) raw tool output, screenshots, JS dumps
├── cache/                       # (gen) content-addressed cache + SQLite db
│
├── utils/
│   ├── __init__.py
│   ├── net.py                   # URL/host parsing, dedup, normalization
│   ├── concurrency.py           # gather_bounded, batched helpers
│   ├── fs.py                    # Atomic writes, path helpers
│   ├── text.py                  # Regex libraries (secrets, endpoints)
│   ├── version.py               # Semver compare for version intelligence
│   └── ux/                      # Console UX (Rich-based)
│       ├── dashboard.py         # Live enterprise dashboard
│       ├── theme.py
│       └── widgets.py
│
├── plugins/                     # Drop-in third-party engines & adapters
│   └── README.md
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── fixtures/                # Recorded tool outputs for offline tests
│   └── conftest.py
│
└── .wolf/                       # Project memory (anatomy, cerebrum, buglog)
```

## Folder Responsibility Rules

- `core/` contains **zero security knowledge** — it is reusable infrastructure.
- `engines/` contain **zero subprocess calls** — they call adapters via the registry.
- `integrations/` contain **zero correlation logic** — they only run tools and normalize.
- `payload_intelligence/` never writes payloads — it only indexes and selects.
- `(gen)` folders are reproducible and safe to delete between scans.

## Naming & Layout Conventions

- One engine = one subpackage with `engine.py`, `models.py` (engine-local), and
  optional `modules/` for internal stages.
- Async public API per engine: `async def run(ctx: ScanContext) -> EngineResult`.
- All cross-engine data flows through `core/models.py` types only.
