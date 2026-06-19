"""ExposureIntelligenceEngine (Stage 15): recon knowledge + exposure change.

Compares this assessment to the project's previous snapshot and answers:
"what changed / appeared / disappeared / became riskier". Writes a new snapshot
and trend point for future comparison. Pure project-memory diff — no network.
"""
from __future__ import annotations

from core import recon_memory as rm
from core.models import ExposureDelta, Severity

from .base import Engine

_KIND_FOR = {
    "assets": ("new_asset", "removed_asset"),
    "endpoints": ("new_endpoint", None),
    "parameters": ("new_parameter", None),
    "services": ("new_service", None),
    "apis": ("new_api", None),
}


class ExposureIntelligenceEngine(Engine):
    name = "exposure_intelligence"
    stage = 15
    depends_on = ("parameter_intelligence", "vulnerability_correlation")

    async def run(self, ctx) -> None:
        roots = ctx.scope.roots
        prev = rm.load_latest(roots)
        snapshot = rm.build_snapshot(ctx.store, ctx.scan_id, roots)
        diff = rm.diff_snapshots(prev, snapshot)

        summary = {"has_baseline": diff["has_baseline"],
                   "previous_scan": diff["previous_scan"], "counts": {}}

        # Asset additions/removals.
        for host in diff["assets"]["added"]:
            ctx.store.add(ExposureDelta(kind="new_asset", subject=host,
                          detail="New asset since last assessment",
                          severity=Severity.LOW))
        for host in diff["assets"]["removed"]:
            ctx.store.add(ExposureDelta(kind="removed_asset", subject=host,
                          detail="Asset no longer observed", severity=Severity.INFO))

        # Endpoints / parameters / services / apis (additions = surface growth).
        for field, kind in [("endpoints", "new_endpoint"),
                            ("parameters", "new_parameter"),
                            ("services", "new_service"), ("apis", "new_api")]:
            for subj in diff[field]["added"][:200]:
                ctx.store.add(ExposureDelta(kind=kind, subject=subj,
                              detail="Newly introduced attack surface",
                              severity=Severity.INFO))

        # Technology changes.
        for tech in diff["technologies"]["added"]:
            ctx.store.add(ExposureDelta(kind="tech_change", subject=tech,
                          detail="New technology detected", severity=Severity.INFO))

        # Newly introduced risk (findings not present before).
        for fkey in diff["findings"]["added"]:
            sev = fkey.split("|", 1)[0]
            try:
                severity = Severity(sev)
            except ValueError:
                severity = Severity.INFO
            ctx.store.add(ExposureDelta(kind="new_risk", subject=fkey.split("|", 2)[1],
                          detail=f"New finding on {fkey.split('|')[-1]}",
                          severity=severity))

        # Trends.
        sev_counts: dict[str, int] = {}
        for f in ctx.store.findings():
            if f.status == "validated":
                sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1
        trends = rm.append_trend(snapshot, sev_counts, roots)
        rm.save_snapshot(snapshot, roots)

        summary["counts"] = {
            "new_assets": len(diff["assets"]["added"]),
            "removed_assets": len(diff["assets"]["removed"]),
            "new_endpoints": len(diff["endpoints"]["added"]),
            "new_parameters": len(diff["parameters"]["added"]),
            "new_services": len(diff["services"]["added"]),
            "new_apis": len(diff["apis"]["added"]),
            "tech_added": len(diff["technologies"]["added"]),
            "new_findings": len(diff["findings"]["added"]),
        }
        # Surface growth = net change in endpoints+assets+services.
        if diff["has_baseline"]:
            growth = (summary["counts"]["new_assets"]
                      + summary["counts"]["new_endpoints"]
                      + summary["counts"]["new_services"])
            summary["surface_growth"] = growth
        ctx.store._exposure = {"summary": summary, "diff": diff,  # type: ignore
                               "trends": trends[-12:]}

        ctx.bus._counters["exposure_changes"] = sum(summary["counts"].values())
        ctx.bus.emit("counter", counter="exposure_changes",
                     value=ctx.bus._counters["exposure_changes"])
        if not diff["has_baseline"]:
            ctx.logger.info("Exposure intelligence: baseline established (first scan)")
        else:
            ctx.logger.info("Exposure intelligence: %d changes vs %s",
                            sum(summary["counts"].values()), diff["previous_scan"])
