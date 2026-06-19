"""RiskScoringEngine (Stage 6): contextual prioritization of findings & assets."""
from __future__ import annotations

from core.models import Risk, Severity

from .base import Engine

_SEV_BASE = {
    Severity.CRITICAL: 90, Severity.HIGH: 70, Severity.MEDIUM: 45,
    Severity.LOW: 20, Severity.INFO: 5,
}


def _band(score: float) -> Severity:
    if score >= 85:
        return Severity.CRITICAL
    if score >= 65:
        return Severity.HIGH
    if score >= 40:
        return Severity.MEDIUM
    if score >= 15:
        return Severity.LOW
    return Severity.INFO


class RiskScoringEngine(Engine):
    name = "risk_scoring"
    stage = 12
    depends_on = ("vulnerability_correlation", "cve_intelligence",
                  "attack_surface_graph")

    async def run(self, ctx) -> None:
        centrality = getattr(ctx.store, "_centrality", {})
        cve_by_asset: dict[str, list] = {}
        for m in ctx.store.cve_matches():
            cve_by_asset.setdefault(m.asset_id, []).append(m)

        for f in ctx.store.findings():
            if f.status != "validated":
                continue
            base = _SEV_BASE[f.severity]
            conf_factor = f.confidence.score
            exploit = 0.0
            for cve in cve_by_asset.get(f.asset_id, []):
                if cve.cve_id in f.cve_ids:
                    if cve.kev:
                        exploit = max(exploit, 15)
                    if (cve.epss or 0) > 0.5:
                        exploit = max(exploit, 10)
            exposure = 10 * centrality.get(f.asset_id, 0.0)
            score = min(100, base * conf_factor + exploit + exposure)
            ctx.store.add(Risk(subject_id=f.id, subject_type="finding",
                               score=round(score, 1), band=_band(score),
                               factors={"base": base, "confidence": conf_factor,
                                        "exploit": exploit,
                                        "exposure": round(exposure, 2)}))

        # Asset-level risk = max of its findings + exposure.
        by_asset: dict[str, float] = {}
        risk_by_finding = {r.subject_id: r.score for r in ctx.store.risks()}
        for f in ctx.store.findings():
            if f.status == "validated":
                by_asset[f.asset_id] = max(by_asset.get(f.asset_id, 0),
                                           risk_by_finding.get(f.id, 0))
        for asset in ctx.store.assets(status="live"):
            score = by_asset.get(asset.id, 0) + 5 * centrality.get(asset.id, 0)
            score = min(100, score)
            ctx.store.add(Risk(subject_id=asset.id, subject_type="asset",
                               score=round(score, 1), band=_band(score)))
        ctx.logger.info("Risk scoring complete")
