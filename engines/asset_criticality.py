"""AssetCriticalityEngine (Stage 15): score every asset's importance & priority.

Answers "what is most exposed?" and "what would an attacker target first?" by
scoring each asset on importance, business impact, exposure, and attack priority.
Additive: does not modify RiskScoring (which scores findings/assets by risk).
"""
from __future__ import annotations

import re

from core.models import AssetCriticality

from .base import Engine

_SENSITIVE_KW = re.compile(
    r"(admin|internal|secure|secret|vault|payment|billing|invoice|account|auth|"
    r"sso|login|api|gateway|backend|db|database|sql|mysql|postgres|redis|mongo|"
    r"jenkins|gitlab|grafana|kibana|jira|confluence|vpn|portal|dashboard|staging|"
    r"dev|test|uat|prod|corp|hr|finance|crm|erp|payroll)", re.I)

_HIGH_RISK_TECH = {"wordpress", "joomla", "drupal", "jenkins", "gitlab",
                   "phpmyadmin", "tomcat", "weblogic", "struts"}


def _band(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    if score >= 15:
        return "low"
    return "info"


class AssetCriticalityEngine(Engine):
    name = "asset_criticality"
    stage = 15
    depends_on = ("technology_detection", "authentication_mapping",
                  "api_discovery", "vulnerability_correlation")

    async def run(self, ctx) -> None:
        techs_by_asset: dict[str, list] = {}
        for t in ctx.store.technologies():
            techs_by_asset.setdefault(t.asset_id, []).append(t)
        auth_by_asset: dict[str, list] = {}
        for a in ctx.store.auth_surfaces():
            auth_by_asset.setdefault(a.asset_id, []).append(a)
        apis_by_asset: dict[str, list] = {}
        for a in ctx.store.api_endpoints():
            apis_by_asset.setdefault(a.asset_id, []).append(a)
        findings_by_asset: dict[str, list] = {}
        for f in ctx.store.findings():
            if f.status == "validated":
                findings_by_asset.setdefault(f.asset_id, []).append(f)
        centrality = getattr(ctx.store, "_centrality", {})

        for asset in ctx.store.assets(status="live"):
            factors: dict[str, float] = {}
            aid = asset.id

            # Authentication / admin functionality.
            auths = auth_by_asset.get(aid, [])
            factors["authentication"] = min(20, 7 * len(auths))
            admin = any(au.kind in ("login", "oauth2", "saml") for au in auths)
            factors["admin_functionality"] = 12 if admin else 0

            # Sensitive keywords in host.
            kw_hits = len(set(_SENSITIVE_KW.findall(asset.host)))
            factors["sensitive_keywords"] = min(18, 6 * kw_hits)

            # Technology risk.
            techs = [t.name.lower() for t in techs_by_asset.get(aid, [])]
            factors["technology_risk"] = min(
                15, 5 * sum(1 for t in techs if any(h in t for h in _HIGH_RISK_TECH)))

            # Internet exposure (live + open services).
            factors["internet_exposure"] = 10 + min(10, 2 * len(asset.ports))

            # Cloud exposure.
            factors["cloud_exposure"] = 10 if (asset.cdn or "cloud" in asset.host) else 0

            # API sensitivity.
            apis = apis_by_asset.get(aid, [])
            factors["api_sensitivity"] = min(15, 3 * len(apis))

            # Graph centrality (pivot importance).
            factors["centrality"] = round(20 * centrality.get(aid, 0.0), 1)

            importance = min(100, sum(factors.values()))
            # Business impact emphasizes sensitivity + auth + api.
            business_impact = min(100, (
                factors["sensitive_keywords"] * 2 + factors["authentication"]
                + factors["api_sensitivity"] + factors["admin_functionality"]))
            exposure = min(100, factors["internet_exposure"] * 2
                           + factors["cloud_exposure"] + factors["technology_risk"])
            # Attack priority blends importance, exposure, and existing findings.
            find = findings_by_asset.get(aid, [])
            find_weight = min(30, sum(f.severity.rank for f in find) * 2)
            attack_priority = min(100, round(
                importance * 0.4 + exposure * 0.3 + business_impact * 0.2
                + find_weight, 1))

            ctx.store.add(AssetCriticality(
                asset_id=aid, host=asset.host,
                importance=round(importance, 1),
                business_impact=round(business_impact, 1),
                exposure=round(exposure, 1),
                attack_priority=attack_priority,
                band=_band(attack_priority), factors=factors))

        ctx.logger.info("Asset criticality scored for %d live assets",
                        ctx.store.count(AssetCriticality)
                        if hasattr(ctx.store, "count") else 0)
