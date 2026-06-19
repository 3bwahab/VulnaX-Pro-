"""ValidationOrchestrationEngine (Stage 8): run active validators per the plan.

Thin engine wrapper over core.orchestration.ValidationOrchestrator. Active/dual-use
tools (dalfox, sqlmap) run only when `assessment.active` is enabled (--active) and
only against in-scope, parameter-prioritized targets chosen by the planner.
"""
from __future__ import annotations

from core.orchestration import AssessmentPlan, ValidationOrchestrator

from .base import Engine


class ValidationOrchestrationEngine(Engine):
    name = "validation_orchestration"
    stage = 8
    depends_on = ("assessment_planner", "extended_detectors")

    async def run(self, ctx) -> None:
        plan: AssessmentPlan | None = getattr(ctx.store, "_plan", None)
        if plan is None:
            ctx.logger.info("No assessment plan; skipping orchestration")
            return
        orchestrator = ValidationOrchestrator(ctx)
        produced = await orchestrator.run_active(plan)
        if produced:
            ctx.logger.info("Active validation produced %d findings", produced)
        ctx.bus._counters["findings"] = sum(
            1 for f in ctx.store.findings() if f.status == "validated")
        ctx.bus.emit("counter", counter="findings",
                     value=ctx.bus._counters["findings"])
