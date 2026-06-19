# 03 — Engine-by-Engine Design

## Engine Contract (`engines/base.py`)

Every engine subclasses `Engine` and honors this lifecycle:

```python
class Engine(ABC):
    name: str
    stage: int
    depends_on: tuple[str, ...] = ()      # engine names
    requires_tools: tuple[str, ...] = ()  # adapter names (capability check)
    optional: bool = False                # pipeline continues if it fails

    async def preflight(self, ctx: ScanContext) -> None: ...   # validate deps/tools
    async def run(self, ctx: ScanContext) -> EngineResult: ... # main work
    async def teardown(self, ctx: ScanContext) -> None: ...    # cleanup

    # helpers provided by base:
    #   self.adapter(name)  -> ToolAdapter via registry
    #   self.emit(event)    -> publish to bus
    #   self.pool(kind)     -> bounded worker pool
    #   self.cached(key, coro) -> content-addressed memo
```

`EngineResult` = `{ engine, status, produced: dict[type,int], metrics, errors }`.
Actual data is written to `ctx.store`; the result is a manifest/summary.

Each engine below documents: **Responsibilities · Inputs · Outputs · Flow ·
Internal Modules · Dependencies · Performance · Extensibility.**

---

## 1. AssetDiscoveryEngine  (Stage 0)

**Responsibilities** — Maximize the set of candidate assets (subdomains, hosts,
IPs) for the in-scope roots.

**Inputs** — root domains/CIDRs from scope.
**Outputs** — `Asset` records (status=`candidate`), `Relationship(domain→subdomain)`.

**Flow**
```
roots → [subfinder, amass(passive), assetfinder, findomain, chaos] (concurrent)
      → CT logs + DNS brute (curated wordlist via PayloadSelector)
      → ASN expansion (org → CIDRs → hosts)
      → reverse DNS on resolved IPs
      → GitHub intelligence (org/repo subdomain & URL mining)
      → normalize + dedup → store as candidate Assets
```

**Internal modules** — `passive.py` (adapter fan-out), `ct_logs.py`, `dns_brute.py`,
`asn.py`, `reverse_dns.py`, `github_recon.py`, `merge.py` (dedup/union).

**Dependencies** — adapters: subfinder, amass, assetfinder, findomain, chaos, dnsx.
**Performance** — all sources run concurrently; results streamed and deduped via a
normalized key (`fqdn.lower().rstrip('.')`); cache keyed on root+source.
**Extensibility** — new passive source = new adapter + add to fan-out list.

---

## 2. AssetValidationEngine  (Stage 1)

**Responsibilities** — Resolve and probe candidates to determine which are live;
collect baseline HTTP metadata.

**Inputs** — candidate `Asset`s.
**Outputs** — `Asset`(status=`live`/`dead`) with `Endpoint`(root URLs), IPs, ASN,
TLS, status code, title, CDN/WAF hints.

**Flow** — `dnsx` resolve (A/AAAA/CNAME) → `httpx` probe (status, title, tech hints,
TLS, redirects, hashes) → mark live/dead → emit `Live Assets` counter.

**Internal modules** — `resolve.py` (dnsx), `probe.py` (httpx batch), `tls.py`,
`cdn_waf.py`.
**Dependencies** — dnsx, httpx. depends_on: AssetDiscovery.
**Performance** — stdin-streamed batches to dnsx/httpx; per-host rate limit; dead
hosts dropped early to shrink downstream surface.
**Extensibility** — pluggable liveness probes (e.g., raw TCP for non-HTTP).

---

## 3. ServiceFingerprintEngine  (Stage 2)

**Responsibilities** — Port + service discovery and protocol-level fingerprinting.

**Inputs** — live `Asset`s + resolved IPs.
**Outputs** — `Service`(host, port, proto, banner, product, version), updated
`Asset.ports`.

**Flow** — `naabu` fast port scan (scope-restricted port set) → service probe
(banner/version) → map services to assets → emit `Services Discovered`.

**Internal modules** — `portscan.py` (naabu), `service_probe.py`, `banner.py`.
**Dependencies** — naabu. depends_on: AssetValidation.
**Performance** — Naabu (SYN) over nmap for speed; top-ports by profile; rate-limited;
results feed CVE intel for version matching.
**Extensibility** — optional nmap deep-probe adapter for high-value hosts only.

---

## 4. TechnologyDetectionEngine  (Stage 2)

**Responsibilities** — Identify technologies, frameworks, CMS, languages, servers,
CDNs, and versions. **This engine is the trigger for Payload Intelligence.**

**Inputs** — live `Asset`s + HTTP responses/headers/bodies + favicon hashes.
**Outputs** — `Technology`(name, category, version, confidence, evidence) attached
to assets; a per-asset **tech profile** used everywhere downstream.

**Flow** — Wappalyzer fingerprints + header/cookie analysis + favicon hash +
JS library detection + meta-generator parsing → consolidate → version inference →
publish tech profile to store → notify PayloadSelector.

**Internal modules** — `wappalyzer.py`, `headers.py`, `favicon.py`, `cookies.py`,
`version_infer.py`, `consolidate.py`.
**Dependencies** — wappalyzer, httpx. depends_on: AssetValidation.
**Performance** — reuses HTTP responses captured in validation (no re-fetch);
favicon hashes cached.
**Extensibility** — custom fingerprint rule packs (yaml).

---

## 5. DeepCrawlerEngine  (Stage 3)

**Responsibilities** — Maximize URL/endpoint coverage across live assets.

**Inputs** — live `Asset`s + tech profiles.
**Outputs** — `Endpoint`(url, method, source, params), discovered JS file list,
forms, sitemap.

**Flow** — `katana` crawl (headless + JS parsing) → directory discovery
(`feroxbuster`/`dirsearch`) with **PayloadSelector-chosen wordlists per tech** →
robots/sitemap parse → form extraction → dedup/normalize URLs → store endpoints.

**Internal modules** — `katana_crawl.py`, `content_discovery.py`, `forms.py`,
`sitemap.py`, `url_normalize.py`.
**Dependencies** — katana, feroxbuster, dirsearch. depends_on: TechnologyDetection.
**Performance** — depth/scope caps per profile; dedup by URL signature
(path + sorted param keys); JS files queued to JS engine via bus.
**Extensibility** — pluggable crawl strategies (SPA-aware vs classic).

---

## 6. JavaScriptIntelligenceEngine  (Stage 4)

**Responsibilities** — Analyze every JS file for hidden surface and secrets.

**Inputs** — JS file URLs from crawler.
**Outputs** — extracted `Endpoint`s, `Finding`s (secrets/tokens), cloud refs,
GraphQL refs, admin/debug routes, and three graphs (JS relationship, endpoint,
dependency).

**Flow** — fetch + (optional) beautify → regex/AST extraction of: endpoints, API
routes, secrets/tokens (entropy + pattern), cloud references (S3/GCS/Azure), GraphQL
operations, auth references, admin routes, debug flags, internal URLs →
source-map recovery (if present) → build graphs → emit findings with evidence.

**Internal modules** — `fetch.py`, `beautify.py`, `extract_endpoints.py`,
`extract_secrets.py` (gitleaks-style rules + entropy), `cloud_refs.py`,
`graphql_refs.py`, `sourcemap.py`, `graphs.py`.
**Dependencies** — httpx (fetch). depends_on: DeepCrawler.
**Performance** — concurrent fetch pool; per-file cache by URL hash; secret rules
compiled once; large files streamed.
**Extensibility** — pluggable extractor rule packs; AST backend swappable.

---

## 7. ApiDiscoveryEngine  (Stage 4)

**Responsibilities** — Identify and characterize APIs (REST, GraphQL, gRPC-web,
SOAP) and their endpoints.

**Inputs** — endpoints (crawler + JS), tech profiles, responses.
**Outputs** — `ApiEndpoint`(path, method, params, auth_required, content_type),
API type classification, schema docs (OpenAPI/Swagger, GraphQL introspection).

**Flow** — detect API surface (paths like `/api`, `/graphql`, content-type
`application/json`) → fetch OpenAPI/Swagger specs → GraphQL introspection (if
enabled & in scope) → parameter & auth inference → store API model.

**Internal modules** — `detect.py`, `openapi.py`, `graphql_introspect.py`,
`grpc_web.py`, `param_infer.py`.
**Dependencies** — httpx. depends_on: DeepCrawler, JSIntelligence.
**Performance** — spec parsing cached; introspection gated by scope/profile.
**Extensibility** — new API-type detectors as modules.

---

## 8. AuthenticationMappingEngine  (Stage 4)

**Responsibilities** — Map authentication & session surfaces.

**Inputs** — endpoints, responses, cookies, JS auth refs, API auth metadata.
**Outputs** — `AuthSurface`(login/SSO/OAuth/SAML/JWT endpoints, session mechanism,
MFA hints, password reset flows), auth-protected vs public classification.

**Flow** — detect login forms & auth endpoints → identify scheme (Basic, JWT, OAuth2,
SAML, session cookie) → cookie security flags (HttpOnly/Secure/SameSite) → map
which endpoints require auth → feed RiskScoring & AttackPath.

**Internal modules** — `detect_login.py`, `scheme.py`, `jwt_analyze.py`,
`cookie_flags.py`, `classify_protected.py`.
**Dependencies** — httpx. depends_on: ApiDiscovery, DeepCrawler.
**Performance** — reuses captured responses; lightweight.
**Extensibility** — pluggable scheme analyzers.

---

## 9. ConfigurationAssessmentEngine  (Stage 5)

**Responsibilities** — Assess misconfigurations and exposures (no exploitation).

**Inputs** — assets, services, endpoints, headers, tech.
**Outputs** — `Finding`s for: missing/weak security headers, CORS misconfig,
exposed admin/debug, directory listing, default creds surfaces, exposed `.git`/
`.env`/backups, TLS issues, cloud bucket exposure, verbose errors.

**Flow** — header policy checks → CORS reflection test → sensitive path checks
(PayloadSelector sensitive-files list) → TLS config eval → cloud exposure checks →
emit findings with evidence + remediation.

**Internal modules** — `headers.py`, `cors.py`, `sensitive_paths.py`, `tls.py`,
`cloud_exposure.py`, `default_creds.py`.
**Dependencies** — httpx. depends_on: TechnologyDetection, DeepCrawler.
**Performance** — checks batched per host; safe (read-only) probes only.
**Extensibility** — declarative check rule packs (yaml).

---

## 10. VulnerabilityCorrelationEngine  (Stage 5)

**Responsibilities** — Produce validated findings by **correlating multiple
evidence sources** — never relying solely on Nuclei.

**Inputs** — tech profiles, services+versions, headers, responses, config findings,
CVE intel, Nuclei output.
**Outputs** — correlated `Finding`s with multi-source evidence, confidence, and
de-duplicated identity.

**Flow**
```
collect signals: nuclei matches + version→CVE matches + config findings
                 + header/response anomalies + exposure indicators
→ group by (asset, vuln-class, signature)
→ correlate: require ≥ N corroborating signals OR one high-confidence signal
→ score confidence (evidence weight model)
→ suppress false positives (heuristics + allowlist)
→ emit consolidated Finding with all evidence attached
```

**Internal modules** — `nuclei_runner.py`, `signal_collect.py`, `correlate.py`,
`confidence.py`, `dedupe.py`, `fp_filter.py`.
**Dependencies** — nuclei, + reads CVEIntel/Config outputs. depends_on:
TechnologyDetection, ServiceFingerprint, ConfigurationAssessment, CVEIntelligence.
**Performance** — Nuclei templates pre-filtered by detected tech (PayloadSelector)
to cut runtime massively; correlation is in-memory graph join.
**Extensibility** — pluggable correlation rules + confidence weights.

---

## 11. CVEIntelligenceEngine  (Stage 5)

**Responsibilities** — Map detected products+versions to known CVEs/exposures.

**Inputs** — `Technology` + `Service` versions.
**Outputs** — `CVEMatch`(cve_id, cvss, epss, kev_flag, affected_range, confidence)
linked to assets; feeds correlation + risk.

**Flow** — normalize product+version → query local CVE dataset (synced NVD/OSV +
CISA KEV + EPSS) → version-range match → attach exploitability signals (KEV/EPSS) →
emit matches with confidence (exact vs range vs heuristic).

**Internal modules** — `dataset.py` (local sync/load), `cpe_match.py`,
`version_range.py`, `enrich.py` (KEV/EPSS).
**Dependencies** — local CVE data (offline-capable). depends_on: TechnologyDetection,
ServiceFingerprint.
**Performance** — in-memory indexed dataset; version matching vectorized; refreshed
on a schedule, not per scan.
**Extensibility** — pluggable feeds (NVD, OSV, GHSA, vendor).

---

## 12. AttackSurfaceGraphEngine  (Stage 6)

**Responsibilities** — Build the unified relationship graph of the whole surface.

**Inputs** — all prior models.
**Outputs** — a property graph (nodes: Asset, Host, Port, Service, Technology,
Endpoint, Api, AuthSurface, JsAsset, CloudResource, Finding, CVE; edges: typed
relationships) + exposure maps + surface summaries.

**Flow** — load typed models from store → instantiate nodes → derive edges
(`asset→host→port→service`, `tech→cve`, `endpoint→auth`, `js→endpoint`, …) →
compute centrality/exposure metrics → persist graph (in `networkx`, serialized).

**Internal modules** — `build.py`, `edges.py`, `metrics.py` (centrality, exposure),
`serialize.py`.
**Dependencies** — `networkx`. depends_on: Stages 0–5.
**Performance** — single pass build; graph kept in memory, serialized to artifacts.
**Extensibility** — new node/edge types via schema registration.

---

## 13. RiskScoringEngine  (Stage 6)

**Responsibilities** — Prioritize findings and assets by contextual risk.

**Inputs** — findings (severity, confidence, evidence), CVE signals (CVSS/EPSS/KEV),
asset criticality, graph centrality, chain potential.
**Outputs** — `Risk`(score, band, factors) per finding & per asset; ranked lists.

**Flow** — base score from severity×confidence → adjust by exploitability
(KEV/EPSS) → adjust by asset exposure/centrality → adjust by chain potential
(does it participate in an attack path?) → normalize to 0–100 + band
(Critical/High/Medium/Low/Info) → rank.

**Internal modules** — `model.py` (scoring formula), `factors.py`, `rank.py`.
**Dependencies** — depends_on: VulnCorrelation, CVEIntel, AttackSurfaceGraph.
**Performance** — pure CPU, vectorized.
**Extensibility** — scoring weights configurable; pluggable risk models.

---

## 14. AttackPathEngine  (Stage 6)

**Responsibilities** — Chain findings into meaningful attack paths & narratives.

**Inputs** — surface graph + findings + auth surfaces + risk.
**Outputs** — `AttackPath`(ordered steps, entry, target, narrative, likelihood,
impact) for: privilege escalation, auth abuse, data exposure, misconfig chains.

**Flow** — overlay findings onto the graph → run path search from likely entry
points (exposed/unauth nodes) toward high-value targets (auth/data/admin) →
score paths (weakest-link × impact) → generate human-readable narratives →
boost RiskScoring for findings on critical paths.

**Internal modules** — `entrypoints.py`, `targets.py`, `search.py` (graph traversal
with capability rules), `score.py`, `narrative.py`.
**Dependencies** — `networkx`. depends_on: AttackSurfaceGraph, RiskScoring,
AuthMapping.
**Performance** — bounded path length & branching; top-K paths retained.
**Extensibility** — declarative path-rule library (capability/transition rules).

---

## 15. AIAnalystEngine  (Stage 7)

**Responsibilities** — LLM-assisted explanation, prioritization, summaries — on
**structured evidence only**. Fully optional/offline-degradable.

**Inputs** — structured findings, paths, risk, evidence (NO raw tool blobs).
**Outputs** — finding explanations, executive summary, remediation guidance, attack
narrative prose, FP-reduction suggestions (advisory, never auto-deletes).

**Flow** — build compact evidence bundles → call provider via `integrations` LLM
adapter (Claude default, model `claude-opus-4-8`) → validate structured response
against schema → attach AI annotations to findings/report. If no key/offline →
deterministic template fallbacks.

**Internal modules** — `bundle.py` (evidence packing), `prompts.py`, `client.py`,
`validate.py`, `fallback.py`.
**Dependencies** — LLM adapter (Anthropic SDK). depends_on: RiskScoring,
AttackPath. optional=True.
**Performance** — batched prompts; cached by evidence hash; token budget guard.
**Extensibility** — provider-agnostic; new models via adapter config.

---

## 16. ReportingEngine  (Stage 8)

**Responsibilities** — Render all report formats from the consolidated model.

**Inputs** — full result set (assets, findings, graph, paths, risk, AI annotations).
**Outputs** — HTML, Markdown, JSON; Executive, Technical, Asset Inventory, Attack
Surface, Attack Path reports.

**Flow** — assemble report model → render Jinja2 templates → embed evidence,
confidence, risk, impact, remediation, references → write to `reports/<scan_id>/`.

**Internal modules** — `assemble.py`, `render_html.py`, `render_md.py`,
`render_json.py`, `evidence_embed.py`.
**Dependencies** — Jinja2. depends_on: all. (See `08_REPORTING.md`.)
**Performance** — streaming render for large datasets; assets table paginated.
**Extensibility** — new templates auto-discovered; custom renderers via plugin.

---

## Engine Dependency Summary

```
AssetDiscovery → AssetValidation → {ServiceFingerprint, TechnologyDetection}
TechnologyDetection → DeepCrawler → {JSIntelligence, ApiDiscovery, AuthMapping}
{Tech, Service, Config, CVEIntel} → VulnerabilityCorrelation
{all Stage0-5} → AttackSurfaceGraph → RiskScoring → AttackPath → AIAnalyst → Reporting
```
