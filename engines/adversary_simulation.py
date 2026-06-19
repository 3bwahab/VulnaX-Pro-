"""AdversarySimulationEngine (Stage 16): evidence-based attacker's-eye view.

Answers "what would an attacker target first / how would they progress" by
composing existing findings, ATT&CK mappings, attack paths, and asset criticality.
Purely synthesizes existing evidence — no new probing.
"""
from __future__ import annotations

from core.models import Severity

from .base import Engine

_ENTRY_CATS = {"exposure", "secret", "vuln", "misconfig"}


class AdversarySimulationEngine(Engine):
    name = "adversary_simulation"
    stage = 16
    depends_on = ("mitre_intelligence", "asset_criticality", "attack_path")

    async def run(self, ctx) -> None:
        findings = [f for f in ctx.store.findings() if f.status == "validated"]
        crit_by_asset = {c.asset_id: c for c in ctx.store.asset_criticality()}
        host_by_asset = {a.id: a.host for a in ctx.store.assets()}
        mitre = getattr(ctx.store, "_mitre", {}) or {}
        mappings = ctx.store.mitre_mappings()
        tech_by_finding: dict[str, str] = {}
        for m in mappings:
            tech_by_finding.setdefault(
                m.finding_id, f"{m.technique_id} {m.technique_name}")

        # Likely objectives = leading ATT&CK tactics observed.
        objectives = mitre.get("tactics", [])[:5]

        # Entry points = medium+ findings of low-friction categories, ranked.
        risk_by_finding = {r.subject_id: r.score for r in ctx.store.risks()
                           if r.subject_type == "finding"}
        entries = sorted(
            [f for f in findings
             if f.category in _ENTRY_CATS and f.severity.rank >= Severity.MEDIUM.rank],
            key=lambda f: risk_by_finding.get(f.id, f.severity.rank * 10),
            reverse=True)[:8]
        entry_points = [{
            "target": f.target, "title": f.title, "severity": f.severity.value,
            "host": host_by_asset.get(f.asset_id, ""),
            "technique": tech_by_finding.get(f.id, "")} for f in entries]

        # Most attractive assets = highest attack priority.
        attractive = sorted(ctx.store.asset_criticality(),
                            key=lambda c: -c.attack_priority)[:6]
        attractive_assets = [{
            "host": c.host, "attack_priority": c.attack_priority, "band": c.band,
            "business_impact": c.business_impact, "exposure": c.exposure}
            for c in attractive]

        # Escalation routes = existing attack paths.
        escalation = [{
            "kind": p.kind, "narrative": p.narrative, "risk": p.risk_score,
            "impact": p.impact.value}
            for p in sorted(ctx.store.attack_paths(), key=lambda p: -p.risk_score)[:5]]

        # Data targets = assets with secrets/cloud/sensitive criticality.
        data_targets = []
        for f in findings:
            if f.category == "secret" or "cloud" in f.title.lower() or (
                    ".env" in f.title.lower() or "git" in f.title.lower()):
                data_targets.append({
                    "host": host_by_asset.get(f.asset_id, ""), "via": f.title,
                    "target": f.target})
        # de-dup by host+title
        seen = set()
        data_targets = [d for d in data_targets
                        if not (k := (d["host"], d["via"])) in seen
                        and not seen.add(k)][:8]

        # Top narrative.
        scenarios = sorted(ctx.store.threat_scenarios(),
                           key=lambda s: -s.risk_score)
        top_narrative = scenarios[0].narrative if scenarios else (
            "An attacker would begin with the highest-priority exposed asset, "
            "leverage the leading entry-point findings, and pivot toward "
            "credential and data targets identified above.")

        ctx.store._adversary = {  # type: ignore[attr-defined]
            "objectives": objectives,
            "entry_points": entry_points,
            "attractive_assets": attractive_assets,
            "escalation_routes": escalation,
            "data_targets": data_targets,
            "narratives": [s.narrative for s in scenarios[:5]],
            "top_narrative": top_narrative,
        }
        ctx.logger.info("Adversary simulation: %d entry points, %d attractive assets, "
                        "%d escalation routes", len(entry_points),
                        len(attractive_assets), len(escalation))
