"""Typed data models — the only contract between engines.

Every cross-engine data flow uses these types. See docs/06_DATA_MODELS.md.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


def _now() -> datetime:
    return datetime.now(timezone.utc)


def stable_id(*parts: Any) -> str:
    """Content-addressed id so the same logical entity is stable across scans."""
    raw = "|".join(str(p) for p in parts)
    return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:16]


# --------------------------------------------------------------------------- #
# Shared value objects
# --------------------------------------------------------------------------- #
class ToolSource(BaseModel):
    name: str
    version: str = "n/a"
    args_hash: str = ""
    collected_at: datetime = Field(default_factory=_now)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}[self.value]


class Confidence(BaseModel):
    score: float = 0.5  # 0..1
    rationale: str = ""
    signals: int = 1


class Evidence(BaseModel):
    kind: Literal[
        "http_response", "header", "banner", "js_match", "version",
        "config", "cve", "behavioral", "dns",
    ]
    summary: str
    data: dict[str, Any] = Field(default_factory=dict)
    artifact_ref: Optional[str] = None
    source: Optional[ToolSource] = None
    weight: float = 0.5


class TlsInfo(BaseModel):
    enabled: bool = False
    version: Optional[str] = None
    issuer: Optional[str] = None
    expires: Optional[str] = None
    san: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Core entities
# --------------------------------------------------------------------------- #
class Asset(BaseModel):
    id: str = ""
    host: str
    type: Literal["domain", "subdomain", "ip", "cidr", "cloud"] = "subdomain"
    status: Literal["candidate", "live", "dead"] = "candidate"
    ips: list[str] = Field(default_factory=list)
    asn: Optional[str] = None
    cname: Optional[str] = None
    ports: list[int] = Field(default_factory=list)
    tls: Optional[TlsInfo] = None
    cdn: Optional[str] = None
    waf: Optional[str] = None
    tags: list[str] = Field(default_factory=list)
    sources: list[ToolSource] = Field(default_factory=list)

    def model_post_init(self, _ctx: Any) -> None:
        if not self.id:
            self.id = stable_id("asset", self.host.lower())


class Service(BaseModel):
    id: str = ""
    asset_id: str
    host: str
    port: int
    protocol: Literal["tcp", "udp"] = "tcp"
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    sources: list[ToolSource] = Field(default_factory=list)

    def model_post_init(self, _ctx: Any) -> None:
        if not self.id:
            self.id = stable_id("service", self.host, self.port, self.protocol)


class Technology(BaseModel):
    id: str = ""
    asset_id: str
    name: str
    category: str = "unknown"
    version: Optional[str] = None
    confidence: float = 0.5
    cpe: Optional[str] = None
    evidence: list[Evidence] = Field(default_factory=list)

    def model_post_init(self, _ctx: Any) -> None:
        if not self.id:
            self.id = stable_id("tech", self.asset_id, self.name.lower())


class Endpoint(BaseModel):
    id: str = ""
    asset_id: str
    url: str
    method: str = "GET"
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    title: Optional[str] = None
    params: list[str] = Field(default_factory=list)
    source: Literal[
        "crawl", "content_discovery", "js", "sitemap", "api", "form", "probe"
    ] = "crawl"
    is_js: bool = False
    sources: list[ToolSource] = Field(default_factory=list)

    def model_post_init(self, _ctx: Any) -> None:
        if not self.id:
            self.id = stable_id("endpoint", self.method, self.url)


class JsAsset(BaseModel):
    id: str = ""
    asset_id: str
    url: str
    sha256: str = ""
    size: int = 0
    endpoints: list[str] = Field(default_factory=list)
    secrets: list[str] = Field(default_factory=list)
    cloud_refs: list[str] = Field(default_factory=list)
    graphql_refs: list[str] = Field(default_factory=list)
    has_sourcemap: bool = False

    def model_post_init(self, _ctx: Any) -> None:
        if not self.id:
            self.id = stable_id("js", self.url)


class ApiEndpoint(BaseModel):
    id: str = ""
    asset_id: str
    type: Literal["rest", "graphql", "grpc-web", "soap"] = "rest"
    path: str
    method: Optional[str] = None
    params: list[str] = Field(default_factory=list)
    auth_required: Optional[bool] = None
    schema_ref: Optional[str] = None

    def model_post_init(self, _ctx: Any) -> None:
        if not self.id:
            self.id = stable_id("api", self.type, self.path)


class AuthSurface(BaseModel):
    id: str = ""
    asset_id: str
    kind: Literal[
        "login", "oauth2", "saml", "jwt", "basic", "session", "mfa", "reset"
    ]
    endpoint: str
    cookie_flags: dict[str, bool] = Field(default_factory=dict)
    notes: Optional[str] = None

    def model_post_init(self, _ctx: Any) -> None:
        if not self.id:
            self.id = stable_id("auth", self.kind, self.endpoint)


class CVEMatch(BaseModel):
    cve_id: str
    asset_id: str
    technology_id: str = ""
    product: str = ""
    cvss: Optional[float] = None
    epss: Optional[float] = None
    kev: bool = False
    affected_range: str = ""
    match_type: Literal["exact", "range", "heuristic"] = "heuristic"
    confidence: float = 0.5


class Finding(BaseModel):
    id: str = ""
    title: str
    category: str = "misc"
    asset_id: str = ""
    target: str = ""
    severity: Severity = Severity.INFO
    confidence: Confidence = Field(default_factory=Confidence)
    evidence: list[Evidence] = Field(default_factory=list)
    impact: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)
    cwe: Optional[str] = None
    status: Literal["validated", "needs_review", "suppressed"] = "validated"
    detected_by: list[str] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=_now)
    ai: Optional["AiAnnotation"] = None

    def model_post_init(self, _ctx: Any) -> None:
        if not self.id:
            self.id = stable_id("finding", self.category, self.target, self.title)


class Risk(BaseModel):
    subject_id: str
    subject_type: Literal["finding", "asset"]
    score: float = 0.0  # 0..100
    band: Severity = Severity.INFO
    factors: dict[str, float] = Field(default_factory=dict)


class Relationship(BaseModel):
    id: str = ""
    src_id: str
    src_type: str
    dst_id: str
    dst_type: str
    kind: str
    weight: float = 1.0

    def model_post_init(self, _ctx: Any) -> None:
        if not self.id:
            self.id = stable_id("rel", self.src_id, self.kind, self.dst_id)


class AttackStep(BaseModel):
    order: int
    node_id: str
    action: str
    evidence_refs: list[str] = Field(default_factory=list)
    finding_id: Optional[str] = None


class AttackPath(BaseModel):
    id: str = ""
    kind: Literal["privesc", "auth_abuse", "data_exposure", "misconfig_chain"]
    entry: str
    target: str
    steps: list[AttackStep] = Field(default_factory=list)
    narrative: str = ""
    likelihood: float = 0.0
    impact: Severity = Severity.INFO
    risk_score: float = 0.0

    def model_post_init(self, _ctx: Any) -> None:
        if not self.id:
            self.id = stable_id("path", self.kind, self.entry, self.target)


class Parameter(BaseModel):
    id: str = ""
    asset_id: str = ""
    name: str
    category: Literal[
        "authentication", "authorization", "object_reference", "search",
        "redirect", "template", "file_handling", "api_control", "administrative",
        "filtering", "pagination", "unknown",
    ] = "unknown"
    risk: Literal["high", "medium", "low", "info"] = "info"
    confidence: float = 0.5
    sources: list[str] = Field(default_factory=list)   # url|form|js|openapi|graphql|api
    locations: list[str] = Field(default_factory=list)  # urls/endpoints seen on
    methods: list[str] = Field(default_factory=list)
    sample_values: list[str] = Field(default_factory=list)
    context: str = ""

    def model_post_init(self, _ctx: Any) -> None:
        if not self.id:
            self.id = stable_id("param", self.asset_id, self.name.lower())


class FindingGroup(BaseModel):
    id: str = ""
    kind: Literal["related", "root_cause", "exposure", "cluster"]
    title: str
    finding_ids: list[str] = Field(default_factory=list)
    root_cause: str = ""
    severity: Severity = Severity.INFO
    risk_score: float = 0.0
    summary: str = ""

    def model_post_init(self, _ctx: Any) -> None:
        if not self.id:
            self.id = stable_id("group", self.kind, self.title)


class AssetCriticality(BaseModel):
    id: str = ""
    asset_id: str
    host: str
    importance: float = 0.0        # 0..100 business/asset importance
    business_impact: float = 0.0   # 0..100
    exposure: float = 0.0          # 0..100 internet/cloud/service exposure
    attack_priority: float = 0.0   # 0..100 combined attacker attractiveness
    band: Literal["critical", "high", "medium", "low", "info"] = "info"
    factors: dict[str, float] = Field(default_factory=dict)

    def model_post_init(self, _ctx: Any) -> None:
        if not self.id:
            self.id = stable_id("crit", self.asset_id)


class ExposureDelta(BaseModel):
    id: str = ""
    kind: Literal[
        "new_asset", "removed_asset", "new_endpoint", "new_parameter",
        "new_service", "new_api", "tech_change", "new_risk",
    ]
    subject: str
    detail: str = ""
    severity: Severity = Severity.INFO

    def model_post_init(self, _ctx: Any) -> None:
        if not self.id:
            self.id = stable_id("delta", self.kind, self.subject)


class InterfaceAsset(BaseModel):
    id: str = ""
    asset_id: str = ""
    url: str
    interface_type: str = "unknown"   # jenkins/grafana/kibana/gitlab/wordpress/...
    confidence: float = 0.5
    title: Optional[str] = None
    evidence: str = ""
    screenshot_path: Optional[str] = None

    def model_post_init(self, _ctx: Any) -> None:
        if not self.id:
            self.id = stable_id("iface", self.url)


class MitreMapping(BaseModel):
    id: str = ""
    finding_id: str = ""
    asset_id: str = ""
    technique_id: str           # e.g. T1190 or T1552.001
    technique_name: str = ""
    sub_technique_id: Optional[str] = None
    tactic_id: str = ""         # e.g. TA0001
    tactic_name: str = ""
    confidence: float = 0.5
    reasoning: str = ""
    mitigations: list[str] = Field(default_factory=list)

    def model_post_init(self, _ctx: Any) -> None:
        if not self.id:
            self.id = stable_id("mitre", self.finding_id, self.technique_id)


class ThreatScenario(BaseModel):
    id: str = ""
    title: str
    asset_id: str = ""
    tactic_chain: list[str] = Field(default_factory=list)   # ordered tactic names
    technique_ids: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    narrative: str = ""
    objective: str = ""
    risk_score: float = 0.0

    def model_post_init(self, _ctx: Any) -> None:
        if not self.id:
            self.id = stable_id("scenario", self.asset_id, self.title)


class AiAnnotation(BaseModel):
    explanation: Optional[str] = None
    prioritization: Optional[str] = None
    remediation_detail: Optional[str] = None
    fp_assessment: Optional[str] = None
    model: str = ""
    evidence_hash: str = ""


Finding.model_rebuild()
