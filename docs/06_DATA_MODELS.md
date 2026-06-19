# 06 — Data Models & Result Schemas

All cross-engine data uses these typed models (`core/models.py`, Pydantic v2).
They are the **only** contract between engines. JSON-Schema is exported from these
models (`core/schemas.py` → `python main.py config show --schemas`).

## 1. Shared Value Objects

```python
class ToolSource(BaseModel):
    name: str
    version: str
    args_hash: str
    collected_at: datetime

class Evidence(BaseModel):
    kind: Literal["http_response","header","banner","js_match","version",
                  "config","cve","behavioral"]
    summary: str                 # human readable
    data: dict[str, Any]         # structured detail (request, snippet, etc.)
    artifact_ref: str | None     # path to raw artifact
    source: ToolSource
    weight: float                # contribution to confidence (0..1)

class Severity(str, Enum):
    CRITICAL="critical"; HIGH="high"; MEDIUM="medium"; LOW="low"; INFO="info"

class Confidence(BaseModel):
    score: float                 # 0..1
    rationale: str
    signals: int                 # number of corroborating evidence items
```

## 2. Core Entities

```python
class Asset(BaseModel):
    id: str                      # stable hash of host
    host: str                    # fqdn or ip
    type: Literal["domain","subdomain","ip","cidr","cloud"]
    status: Literal["candidate","live","dead"]
    ips: list[str] = []
    asn: str | None = None
    cname: str | None = None
    ports: list[int] = []
    tls: TlsInfo | None = None
    cdn: str | None = None
    waf: str | None = None
    tags: list[str] = []
    sources: list[ToolSource] = []

class Service(BaseModel):
    id: str
    asset_id: str
    host: str
    port: int
    protocol: Literal["tcp","udp"]
    service: str | None          # http, ssh, mysql...
    product: str | None
    version: str | None
    banner: str | None
    sources: list[ToolSource] = []

class Technology(BaseModel):
    id: str
    asset_id: str
    name: str
    category: str                # cms, framework, language, server, cdn, js-lib
    version: str | None
    confidence: float
    evidence: list[Evidence] = []
    cpe: str | None = None       # for CVE matching

class Endpoint(BaseModel):
    id: str
    asset_id: str
    url: str
    method: str = "GET"
    status_code: int | None = None
    content_type: str | None = None
    title: str | None = None
    params: list[str] = []
    source: Literal["crawl","content_discovery","js","sitemap","api","form"]
    is_js: bool = False
    sources: list[ToolSource] = []

class JsAsset(BaseModel):
    id: str
    asset_id: str
    url: str
    sha256: str
    size: int
    endpoints: list[str] = []     # extracted
    secrets: list[str] = []       # finding ids
    cloud_refs: list[str] = []
    graphql_refs: list[str] = []
    has_sourcemap: bool = False

class ApiEndpoint(BaseModel):
    id: str
    asset_id: str
    type: Literal["rest","graphql","grpc-web","soap"]
    path: str
    method: str | None
    params: list[str] = []
    auth_required: bool | None = None
    schema_ref: str | None = None  # openapi/introspection artifact

class AuthSurface(BaseModel):
    id: str
    asset_id: str
    kind: Literal["login","oauth2","saml","jwt","basic","session","mfa","reset"]
    endpoint: str
    cookie_flags: dict[str, bool] = {}
    notes: str | None = None
```

## 3. Findings, CVEs, Risk

```python
class Finding(BaseModel):
    id: str
    title: str
    category: str                # misconfig, exposure, vuln, secret...
    asset_id: str
    target: str                  # url/host:port the finding applies to
    severity: Severity
    confidence: Confidence
    evidence: list[Evidence]     # REQUIRED, non-empty
    impact: str
    remediation: str
    references: list[str] = []
    cve_ids: list[str] = []
    cwe: str | None = None
    status: Literal["validated","needs_review","suppressed"] = "validated"
    detected_by: list[str] = []  # engine/tool names (provenance)
    first_seen: datetime
    ai: AiAnnotation | None = None

class CVEMatch(BaseModel):
    cve_id: str
    asset_id: str
    technology_id: str
    cvss: float | None
    epss: float | None
    kev: bool = False
    affected_range: str
    match_type: Literal["exact","range","heuristic"]
    confidence: float

class Risk(BaseModel):
    subject_id: str              # finding id or asset id
    subject_type: Literal["finding","asset"]
    score: float                 # 0..100
    band: Severity
    factors: dict[str, float]    # severity, exploitability, exposure, chain...
```

## 4. Graph & Attack Path

```python
class Relationship(BaseModel):
    id: str
    src_id: str
    src_type: str
    dst_id: str
    dst_type: str
    kind: str                    # hosts, exposes, runs, links_to, requires_auth...
    weight: float = 1.0

class AttackStep(BaseModel):
    order: int
    node_id: str
    action: str                  # "Access exposed .git", "Recover creds"...
    evidence_refs: list[str]
    finding_id: str | None

class AttackPath(BaseModel):
    id: str
    kind: Literal["privesc","auth_abuse","data_exposure","misconfig_chain"]
    entry: str                   # node id
    target: str                  # node id
    steps: list[AttackStep]
    narrative: str
    likelihood: float            # 0..1
    impact: Severity
    risk_score: float            # 0..100
```

## 5. AI Annotation

```python
class AiAnnotation(BaseModel):
    explanation: str | None = None
    prioritization: str | None = None
    remediation_detail: str | None = None
    fp_assessment: str | None = None    # advisory only
    model: str                          # e.g. claude-opus-4-8
    evidence_hash: str                  # what it was given (no raw blobs)
```

## 6. Result Bundle (the scan output)

`output/<scan_id>/result.json` — top-level schema:

```jsonc
{
  "scan": { "id", "started_at", "finished_at", "profile", "scope", "tool_versions" },
  "summary": {
    "assets_found", "live_assets", "technologies", "urls", "js_files",
    "api_endpoints", "findings_by_severity", "critical_paths"
  },
  "assets":        [Asset...],
  "services":      [Service...],
  "technologies":  [Technology...],
  "endpoints":     [Endpoint...],
  "js_assets":     [JsAsset...],
  "api_endpoints": [ApiEndpoint...],
  "auth_surfaces": [AuthSurface...],
  "cve_matches":   [CVEMatch...],
  "findings":      [Finding...],
  "risks":         [Risk...],
  "relationships": [Relationship...],
  "attack_paths":  [AttackPath...],
  "metrics":       { per-engine timing/throughput/errors/cache }
}
```

## 7. Schema Governance

- Models are versioned (`schema_version` in the bundle). Breaking changes bump it.
- JSON-Schema is generated and committed to `config/schema/` for external consumers.
- Every model has a stable `id` (content hash) enabling cross-scan diffing
  (regression / new-finding detection between runs).
- **Invariant:** a `Finding` with empty `evidence` is rejected at validation time.
