"""FindingCorrelationEngine V2 (Stage 10): group findings for explainability.

Produces Related Finding Groups, Root Cause Groups, Exposure Groups, and Risk
Clusters from the validated finding set. Does not modify VulnerabilityCorrelation.
"""
from __future__ import annotations

from collections import defaultdict

from core.models import FindingGroup, Severity

from .base import Engine

# Root-cause mapping: finding category/keyword -> root cause label.
_ROOT_CAUSE = [
    (("secret",), "Secrets exposed in client-side / public assets"),
    (("missing hsts", "content-security-policy", "x-frame", "x-content-type"),
     "Incomplete security-header baseline"),
    (("cors",), "Permissive cross-origin policy"),
    (("git", ".env", "config", "backup", "artifact"),
     "Sensitive files/artifacts publicly served"),
    (("tls", "certificate"), "Weak transport security configuration"),
    (("jwt", "oauth", "session", "cookie", "auth"),
     "Authentication / session hardening gaps"),
    (("cve", "vulnerable to"), "Outdated components with known CVEs"),
    (("graphql", "introspection", "api"), "API exposure / misconfiguration"),
    (("redirect", "traversal", "injection", "idor", "ssrf", "candidate"),
     "Unvalidated input handling"),
    (("admin", "debug", "directory listing", "metrics", "kubernetes", "registry"),
     "Exposed operational / administrative surface"),
]

_SEV_SCORE = {Severity.CRITICAL: 90, Severity.HIGH: 70, Severity.MEDIUM: 45,
              Severity.LOW: 20, Severity.INFO: 5}


def _root_cause(title: str, category: str) -> str:
    hay = f"{title} {category}".lower()
    for keys, label in _ROOT_CAUSE:
        if any(k in hay for k in keys):
            return label
    return "Other"


class FindingCorrelationEngine(Engine):
    name = "finding_correlation"
    stage = 10
    depends_on = ("vulnerability_correlation",)

    async def run(self, ctx) -> None:
        findings = [f for f in ctx.store.findings() if f.status == "validated"]
        risk_by_finding = {r.subject_id: r.score for r in ctx.store.risks()
                           if r.subject_type == "finding"}

        # 1) Related groups: same asset + same category.
        related: dict[tuple, list] = defaultdict(list)
        for f in findings:
            related[(f.asset_id, f.category)].append(f)
        for (asset_id, cat), group in related.items():
            if len(group) < 2:
                continue
            self._add_group(ctx, "related",
                            f"{cat} findings clustered on one asset", group,
                            risk_by_finding, root=_root_cause(group[0].title, cat))

        # 2) Root-cause groups: across assets by shared root cause.
        by_root: dict[str, list] = defaultdict(list)
        for f in findings:
            by_root[_root_cause(f.title, f.category)].append(f)
        for root, group in by_root.items():
            if root == "Other" or len(group) < 2:
                continue
            self._add_group(ctx, "root_cause", root, group, risk_by_finding, root=root)

        # 3) Exposure groups: all exposure/secret/config-class findings per asset.
        exposure_cats = {"exposure", "secret", "config"}
        by_asset_exp: dict[str, list] = defaultdict(list)
        for f in findings:
            if f.category in exposure_cats:
                by_asset_exp[f.asset_id].append(f)
        for asset_id, group in by_asset_exp.items():
            if len(group) < 2:
                continue
            host = self._host(ctx, asset_id)
            self._add_group(ctx, "exposure", f"Exposure surface on {host}", group,
                            risk_by_finding,
                            root="Sensitive files/artifacts publicly served")

        # 4) Risk clusters: high-risk findings (any) into a prioritized cluster.
        high_risk = [f for f in findings
                     if risk_by_finding.get(f.id, _SEV_SCORE[f.severity]) >= 65]
        if high_risk:
            self._add_group(ctx, "cluster", "Top risk cluster (immediate attention)",
                            high_risk, risk_by_finding,
                            root="Highest-impact issues across the attack surface")

        ctx.logger.info("Finding correlation: %d groups", ctx.store.count(FindingGroup)
                        if hasattr(ctx.store, "count") else 0)

    def _add_group(self, ctx, kind, title, group, risk_by_finding, root="") -> None:
        max_sev = max((f.severity for f in group), key=lambda s: s.rank)
        score = max((risk_by_finding.get(f.id, _SEV_SCORE[f.severity])
                     for f in group), default=0)
        ctx.store.add(FindingGroup(
            kind=kind, title=title, finding_ids=[f.id for f in group],
            root_cause=root, severity=max_sev, risk_score=round(score, 1),
            summary=f"{len(group)} findings; max severity {max_sev.value}; "
                    f"root cause: {root or 'n/a'}."))

    def _host(self, ctx, asset_id) -> str:
        for a in ctx.store.assets():
            if a.id == asset_id:
                return a.host
        return asset_id
