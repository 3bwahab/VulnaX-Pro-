"""SecurityPostureEngine (Stage 16): overall posture scoring & indices.

Answers "what is our overall security posture?" with executive-grade indices
derived from the whole assessment. Additive: reads store + prior overlays.
"""
from __future__ import annotations

from core.models import Severity

from .base import Engine


def _grade(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 55:
        return "D"
    return "F"


class SecurityPostureEngine(Engine):
    name = "security_posture"
    stage = 16
    depends_on = ("asset_criticality", "vulnerability_correlation",
                  "mitre_intelligence")

    async def run(self, ctx) -> None:
        live = ctx.store.assets(status="live")
        n_assets = max(len(live), 1)
        findings = [f for f in ctx.store.findings() if f.status == "validated"]
        techs = ctx.store.technologies()
        services = ctx.store.services()
        endpoints = ctx.store.endpoints()

        sev_counts: dict[str, int] = {}
        for f in findings:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

        # --- component metrics (0..100, higher = better posture) ----------
        # Attack surface complexity (more surface -> lower score).
        surface = len(endpoints) + len(services) * 3 + len(live)
        complexity = max(0, 100 - min(100, surface / 5))

        # Technology diversity (more distinct stacks -> larger surface).
        distinct_tech = len({t.name for t in techs})
        tech_diversity = max(0, 100 - min(100, distinct_tech * 4))

        # Exposure density (findings per asset).
        density = len(findings) / n_assets
        exposure_density = max(0, 100 - min(100, density * 25))

        # Authentication maturity (cookie flags + MFA hints + auth coverage).
        auths = ctx.store.auth_surfaces()
        good_cookie = sum(1 for a in auths if all(
            a.cookie_flags.get(k) for k in ("httponly", "secure", "samesite")))
        auth_maturity = 50 + (40 * good_cookie / max(len(auths), 1)) if auths else 70

        # Cloud risk (cloud exposure findings).
        cloud_findings = sum(1 for f in findings if "cloud" in f.title.lower())
        cloud_risk = max(0, 100 - cloud_findings * 20)

        # Configuration quality (misconfig findings weigh negatively).
        misconfig = sum(1 for f in findings if f.category in ("misconfig", "config"))
        config_quality = max(0, 100 - min(100, misconfig * 6))

        # Security header coverage (inverse of missing-header findings).
        header_missing = sum(1 for f in findings if "header" in f.title.lower())
        header_coverage = max(0, 100 - min(100, header_missing * 10))

        components = {
            "attack_surface_complexity": round(complexity, 1),
            "technology_diversity": round(tech_diversity, 1),
            "exposure_density": round(exposure_density, 1),
            "authentication_maturity": round(auth_maturity, 1),
            "cloud_risk": round(cloud_risk, 1),
            "configuration_quality": round(config_quality, 1),
            "security_header_coverage": round(header_coverage, 1),
        }

        # Critical/high findings drag the overall score down hard.
        crit_penalty = sev_counts.get("critical", 0) * 8 + sev_counts.get("high", 0) * 4
        overall = max(0, round(
            sum(components.values()) / len(components) - crit_penalty, 1))

        # Indices.
        risk_index = min(100, round(
            sev_counts.get("critical", 0) * 12 + sev_counts.get("high", 0) * 7
            + sev_counts.get("medium", 0) * 3 + sev_counts.get("low", 0), 1))
        exposure_index = min(100, round(density * 20 + len(services) * 2, 1))
        maturity_index = round(
            (components["authentication_maturity"]
             + components["configuration_quality"]
             + components["security_header_coverage"]) / 3, 1)

        posture = {
            "overall_score": overall, "grade": _grade(overall),
            "components": components,
            "risk_index": risk_index, "exposure_index": exposure_index,
            "maturity_index": maturity_index,
            "findings_by_severity": sev_counts,
            "mitre_coverage": getattr(ctx.store, "_mitre", {}).get("coverage", 0),
        }
        ctx.store._posture = posture  # type: ignore[attr-defined]

        ctx.bus._counters["posture_score"] = int(overall)
        ctx.bus.emit("counter", counter="posture_score", value=int(overall))
        ctx.logger.info("Security posture: %.1f (grade %s), risk index %.1f",
                        overall, posture["grade"], risk_index)
