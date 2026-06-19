# 04 — Integration Architecture (Tool Adapter Layer)

## 1. Goal

Every external tool is reached **only** through a unified adapter. Engines never
spawn processes or parse raw output. Adapters convert messy tool output into the
typed models in `core/models.py`.

## 2. Adapter Contract (`integrations/base.py`)

```python
class ToolAdapter(ABC):
    name: str                      # "subfinder"
    binary: str                    # resolved executable
    capabilities: set[Capability]  # {SUBDOMAIN_ENUM}
    produces: tuple[type, ...]     # (Asset, Relationship)

    async def version(self) -> str: ...
    async def healthcheck(self) -> AdapterHealth: ...   # binary present + runnable
    async def run(self, request: ToolRequest) -> AdapterResult: ...

    # provided by base:
    #   self.process  -> async subprocess runner
    #   self.normalize(raw) -> list[model]   (subclass implements parser)
    #   retry/timeout/ratelimit wrappers applied automatically
```

```python
@dataclass
class ToolRequest:
    targets: list[str]
    options: dict[str, Any]        # adapter-specific, validated
    timeout_s: float
    rate: RatePolicy
    retry: RetryPolicy
    cache_key: str | None

@dataclass
class AdapterResult:
    models: list[BaseModel]        # normalized typed output
    raw_path: Path | None          # raw output archived to artifacts/
    metrics: AdapterMetrics        # duration, rc, bytes, item_count
    version: str
    errors: list[AdapterError]
```

### Mandatory adapter services (every adapter, for free via base)
- **Execution abstraction** — uniform `run()` over heterogeneous CLIs.
- **Output normalization** — raw → typed models via `normalize()`.
- **Error handling** — non-zero exit, stderr capture, partial-output recovery.
- **Version tracking** — `version()` recorded per run for reproducibility.
- **Retry support** — policy-driven, idempotent retries with backoff.
- **Performance metrics** — duration, throughput, exit code, bytes.
- **Timeout management** — hard timeout + process-tree kill.
- **Result validation** — schema-validate normalized models; drop malformed.

## 3. Process Runner (`integrations/process.py`)

Async subprocess execution:
- streams stdout line-by-line (so adapters parse incrementally + emit progress),
- enforces timeout with kill of the whole process tree (Windows: `taskkill /T`,
  POSIX: process group),
- captures stderr to artifacts,
- supports **stdin streaming** for batch tools (httpx, dnsx, naabu, katana) — pipe
  thousands of targets without arg-length limits,
- returns exit code + timing.

## 4. Registry & Capability Map (`integrations/registry.py`)

Adapters self-register with capabilities. Engines request *capabilities*, not
tool names, so tools are swappable.

```python
class Capability(Enum):
    SUBDOMAIN_ENUM, DNS_RESOLVE, PORT_SCAN, HTTP_PROBE, CRAWL,
    CONTENT_DISCOVERY, TEMPLATE_SCAN, TECH_FINGERPRINT = auto()...
```

| Adapter | Capability | Normalized Output |
|---------|-----------|-------------------|
| subfinder | SUBDOMAIN_ENUM | Asset, Relationship |
| amass | SUBDOMAIN_ENUM | Asset, Relationship |
| assetfinder | SUBDOMAIN_ENUM | Asset |
| findomain | SUBDOMAIN_ENUM | Asset |
| chaos | SUBDOMAIN_ENUM | Asset |
| dnsx | DNS_RESOLVE | Asset (IP/CNAME), Relationship |
| naabu | PORT_SCAN | Service, Asset.ports |
| httpx | HTTP_PROBE | Asset(live), Endpoint, Technology(hints) |
| katana | CRAWL | Endpoint, JsAsset, Form |
| feroxbuster | CONTENT_DISCOVERY | Endpoint |
| dirsearch | CONTENT_DISCOVERY | Endpoint |
| nuclei | TEMPLATE_SCAN | Finding, Evidence |
| wappalyzer | TECH_FINGERPRINT | Technology |

**Selection policy:** when multiple adapters provide a capability, the registry
picks by config preference + healthcheck (e.g., prefer `feroxbuster`, fall back to
`dirsearch`). Discovery runs *all* SUBDOMAIN_ENUM adapters and unions results.

## 5. Normalization (`integrations/normalizers.py`)

Each tool has a parser turning its native format (JSON lines / text / XML) into
typed models. Rules:
- Normalize hosts to lowercase FQDN, strip trailing dot.
- Normalize URLs (scheme, default ports, sort query keys) for dedup.
- Every model carries `source=ToolSource(name, version, args_hash)` for provenance.
- Malformed records are logged and skipped, never crash the parser.

Example (httpx JSONL → models):
```python
def normalize_httpx(line: dict) -> list[BaseModel]:
    asset = Asset(host=line["host"], status="live", ip=line.get("a", []),
                  source=src)
    ep = Endpoint(url=line["url"], status_code=line["status_code"],
                  title=line.get("title"), tech_hints=line.get("tech", []),
                  source=src)
    techs = [Technology(name=t, confidence=0.5, source=src) for t in line.get("tech", [])]
    return [asset, ep, *techs]
```

## 6. Health, Versioning & Bootstrap

At startup `registry.healthcheck_all()` runs: verifies each configured binary
exists and reports version. Missing tools → the depending engine is marked
degraded (skipped with a warning), pipeline continues. `config/tools.yaml` pins
expected versions and binary paths.

## 7. Reliability Wrappers (applied by base)

```
run() = ratelimit( retry( timeout( process.exec ) ) )  → normalize → validate → cache
```
- **Rate limit:** token bucket (global + per-host + per-tool).
- **Retry:** exp backoff + jitter; circuit breaker opens after consecutive failures.
- **Timeout:** per-request hard cap; kill tree on expiry.
- **Cache:** if `cache_key` present and hit, skip execution entirely.

## 8. LLM Adapter (for AIAnalystEngine)

A non-tool adapter under the same layer: `integrations/llm/anthropic.py`. Wraps the
Anthropic SDK, default model `claude-opus-4-8`, with the same retry/timeout/metrics
plumbing. Provider-agnostic interface so other LLMs can be added. Consumes only
structured evidence bundles; returns schema-validated JSON.

## 9. Adding a New Tool (recipe)

1. Create `integrations/<tool>.py` subclassing `ToolAdapter`.
2. Declare `name`, `binary`, `capabilities`, `produces`.
3. Implement `normalize(raw)` → typed models.
4. Add binary path/version to `config/tools.yaml`.
5. Register (auto-discovered via registry scan). Done — engines pick it up by
   capability.
