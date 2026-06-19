"""AssessmentPlannerEngine (Stage 6): technology-aware decision engine.

Uses technologies, frameworks, auth mapping, parameter intelligence, API & JS
discovery to decide which assessments are relevant — reducing unnecessary testing.
"""
from __future__ import annotations

from core.orchestration import AssessmentPlan

from .base import Engine

# Tech name (lowercased substring) -> assessment module label.
_TECH_MODULES = {
    "laravel": "laravel", "wordpress": "wordpress", "drupal": "drupal",
    "joomla": "joomla", "spring": "spring", "django": "django",
    "express": "nodejs", "asp.net": "aspnet", "graphql": "graphql",
}

# Parameter categories that warrant active XSS / SQLi validation.
_XSS_CATS = {"redirect", "search", "template", "api_control", "filtering"}
_SQLI_CATS = {"object_reference", "filtering", "search", "pagination"}


class AssessmentPlannerEngine(Engine):
    name = "assessment_planner"
    stage = 6
    depends_on = ("parameter_intelligence", "technology_detection",
                  "authentication_mapping", "api_discovery")

    async def run(self, ctx) -> None:
        techs = [t.name.lower() for t in ctx.store.technologies()]
        modules: set[str] = set()
        for t in techs:
            for key, mod in _TECH_MODULES.items():
                if key in t:
                    modules.add(mod)

        # Nuclei tags via payload intelligence per asset (tech-scoped).
        tags: set[str] = set()
        for a in ctx.store.assets(status="live"):
            sel = ctx.payloads.select([x.name for x in ctx.store.technologies_for(a.id)])
            tags.update(sel.nuclei_tags)

        xss_targets: list[str] = []
        sqli_targets: list[str] = []
        for p in ctx.store.parameters():
            urls = self._candidate_urls(p)
            if p.category in _XSS_CATS:
                xss_targets.extend(urls)
            if p.category in _SQLI_CATS:
                sqli_targets.extend(urls)

        graphql = [a.path for a in ctx.store.api_endpoints() if a.type == "graphql"]
        content_targets = [f"https://{a.host}" for a in ctx.store.assets(status="live")]

        plan = AssessmentPlan(
            tech_modules=sorted(modules), nuclei_tags=sorted(tags),
            xss_targets=_dedup(xss_targets), sqli_targets=_dedup(sqli_targets),
            content_targets=content_targets, graphql_endpoints=graphql,
            rationale=(f"Planned from {len(techs)} tech signals, "
                       f"{len(ctx.store.parameters())} parameters, "
                       f"{len(graphql)} GraphQL endpoints."))
        ctx.store._plan = plan  # type: ignore[attr-defined]
        ctx.logger.info("Assessment plan: %s | %s", plan.summary(), plan.rationale)

    def _candidate_urls(self, param) -> list[str]:
        out: list[str] = []
        for loc in param.locations[:10]:
            if not loc.startswith("http"):
                continue
            out.append(loc if "?" in loc else f"{loc}?{param.name}=1")
        return out


def _dedup(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for i in items:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out
