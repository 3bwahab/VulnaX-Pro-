"""AttackPathEngine (Stage 6): chain findings into meaningful attack paths."""
from __future__ import annotations

from core.models import AttackPath, AttackStep, Risk, Severity

from .base import Engine

_ENTRY_CATEGORIES = {"secret", "exposure", "misconfig", "vuln"}


class AttackPathEngine(Engine):
    name = "attack_path"
    stage = 13
    depends_on = ("attack_surface_graph", "risk_scoring",
                  "authentication_mapping")

    async def run(self, ctx) -> None:
        findings = [f for f in ctx.store.findings() if f.status == "validated"]
        by_asset: dict[str, list] = {}
        for f in findings:
            by_asset.setdefault(f.asset_id, []).append(f)

        auth_by_asset: dict[str, list] = {}
        for au in ctx.store.auth_surfaces():
            auth_by_asset.setdefault(au.asset_id, []).append(au)
        cve_by_asset: dict[str, list] = {}
        for m in ctx.store.cve_matches():
            cve_by_asset.setdefault(m.asset_id, []).append(m)

        critical = 0
        for asset in ctx.store.assets(status="live"):
            entries = [f for f in by_asset.get(asset.id, [])
                       if f.category in _ENTRY_CATEGORIES
                       and f.severity.rank >= Severity.MEDIUM.rank]
            if not entries:
                continue
            entries.sort(key=lambda f: f.severity.rank, reverse=True)
            entry = entries[0]

            path = self._build_path(ctx, asset, entry,
                                    auth_by_asset.get(asset.id, []),
                                    cve_by_asset.get(asset.id, []),
                                    by_asset.get(asset.id, []))
            if path:
                ctx.store.add(path)
                # Chain boost: bump risk of participating findings.
                for step in path.steps:
                    if step.finding_id:
                        ctx.store.add(Risk(
                            subject_id=step.finding_id, subject_type="finding",
                            score=min(100, path.risk_score + 5),
                            band=path.impact))
                if path.impact.rank >= Severity.HIGH.rank:
                    critical += 1

        ctx.bus._counters["critical_paths"] = critical
        ctx.bus.emit("counter", counter="critical_paths", value=critical)
        ctx.logger.info("Attack paths: %d (%d critical)",
                        ctx.store.count(AttackPath), critical)

    def _build_path(self, ctx, asset, entry, auths, cves, all_findings) -> AttackPath:
        steps = [AttackStep(order=1, node_id=asset.id,
                            action=f"Exploit: {entry.title}",
                            evidence_refs=[e.summary for e in entry.evidence[:1]],
                            finding_id=entry.id)]
        kind = "data_exposure"
        impact = entry.severity
        narrative_parts = [
            f"An attacker reaches {asset.host} and exploits '{entry.title}'"
        ]

        if entry.category == "secret":
            kind = "auth_abuse"
            if auths:
                steps.append(AttackStep(
                    order=2, node_id=f"auth:{auths[0].id}",
                    action=f"Use leaked credential against {auths[0].kind} surface"))
                narrative_parts.append(
                    f"leaking a credential usable against the {auths[0].kind} surface")
                impact = Severity.HIGH if impact.rank < 4 else impact
        elif cves:
            kind = "privesc"
            top = max(cves, key=lambda c: c.cvss or 0)
            steps.append(AttackStep(order=2, node_id=f"cve:{top.cve_id}",
                                    action=f"Leverage {top.cve_id} on the host"))
            narrative_parts.append(
                f"then leverages {top.cve_id}"
                + (" (CISA KEV)" if top.kev else "") + " for deeper access")
            impact = Severity.CRITICAL if top.kev else Severity.HIGH
        elif "git" in entry.title.lower() or "env" in entry.title.lower():
            kind = "data_exposure"
            steps.append(AttackStep(order=2, node_id=asset.id,
                                    action="Recover source/config; harvest secrets"))
            narrative_parts.append(
                "recovering source code or configuration containing secrets")
            impact = Severity.HIGH if impact.rank < 4 else impact

        steps.append(AttackStep(order=len(steps) + 1, node_id=asset.id,
                                action="Access sensitive data / expand foothold"))
        narrative_parts.append("ultimately accessing sensitive data on the asset.")

        likelihood = round(
            sum(f.confidence.score for f in all_findings[:3])
            / max(len(all_findings[:3]), 1), 2)
        risk_score = min(100, {
            Severity.CRITICAL: 90, Severity.HIGH: 72, Severity.MEDIUM: 50,
            Severity.LOW: 25, Severity.INFO: 5}[impact] * (0.6 + 0.4 * likelihood))

        return AttackPath(
            kind=kind, entry=entry.id, target=asset.id, steps=steps,
            narrative=", ".join(narrative_parts), likelihood=likelihood,
            impact=impact, risk_score=round(risk_score, 1))
