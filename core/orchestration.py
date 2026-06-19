"""Validation Orchestration: coordinate external assessment tools safely.

Responsibilities: tool scheduling, scope enforcement, input/result normalization,
evidence collection, confidence scoring, duplicate reduction, retries & timeouts.
Adapters do the per-tool normalization; the orchestrator coordinates them.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from integrations.base import Capability, ToolRequest


@dataclass
class AssessmentPlan:
    """Technology-aware decision output: what to run and where."""
    tech_modules: list[str] = field(default_factory=list)
    nuclei_tags: list[str] = field(default_factory=list)
    xss_targets: list[str] = field(default_factory=list)
    sqli_targets: list[str] = field(default_factory=list)
    content_targets: list[str] = field(default_factory=list)
    graphql_endpoints: list[str] = field(default_factory=list)
    rationale: str = ""

    def summary(self) -> str:
        return (f"modules={self.tech_modules or ['generic']} "
                f"xss={len(self.xss_targets)} sqli={len(self.sqli_targets)} "
                f"nuclei_tags={len(self.nuclei_tags)}")


class ValidationOrchestrator:
    def __init__(self, ctx):
        self.ctx = ctx

    def _in_scope(self, targets: list[str]) -> list[str]:
        return [t for t in targets if self.ctx.in_scope(t)]

    async def run_active(self, plan: AssessmentPlan) -> int:
        """Run active/dual-use validators (XSS, SQLi). Gated by config + scope."""
        ctx = self.ctx
        if not ctx.config.get("assessment.active", False):
            ctx.logger.info("Active validation disabled (use --active to enable)")
            return 0

        produced = 0
        timeout = ctx.config.get("assessment.active_timeout", 240.0)

        # XSS validation (dalfox).
        xss_targets = self._in_scope(plan.xss_targets)[
            : ctx.config.get("assessment.max_active_targets", 50)]
        for adapter in ctx.adapters.available(Capability.XSS_SCAN):
            if not xss_targets:
                break
            produced += await self._run_adapter(adapter, xss_targets, timeout)

        # SQLi validation (sqlmap).
        sqli_targets = self._in_scope(plan.sqli_targets)[
            : ctx.config.get("assessment.max_active_targets", 50)]
        for adapter in ctx.adapters.available(Capability.SQLI_SCAN):
            if not sqli_targets:
                break
            produced += await self._run_adapter(adapter, sqli_targets, timeout)

        return produced

    async def _run_adapter(self, adapter, targets, timeout) -> int:
        ctx = self.ctx
        from core.models import Finding

        try:
            ctx.logger.info("Orchestrator running %s on %d targets",
                            adapter.name, len(targets))
            res = await adapter.run(ToolRequest(targets=targets, timeout_s=timeout))
        except Exception as exc:  # noqa: BLE001
            ctx.logger.warning("Adapter %s failed: %s", adapter.name, exc)
            return 0
        n = 0
        for m in res.models:
            if isinstance(m, Finding):
                m.detected_by = list(set(m.detected_by + [adapter.name]))
                ctx.store.add(m)
                ctx.bus.incr("findings")
                n += 1
        return n
