"""AIAnalystEngine (Stage 7): LLM explanation on structured evidence only.

Provider-agnostic: uses whichever LLM is configured/available (Anthropic, Gemini,
DeepSeek, Kimi/Moonshot, OpenRouter). Falls back to deterministic offline output
so the framework always produces explanations.
"""
from __future__ import annotations

import hashlib
import json

from core.models import AiAnnotation, Severity

from .base import Engine

_SYSTEM = ("You are a senior security analyst. Use ONLY the structured evidence "
           "provided. Be precise and concise. Never invent details.")


class AIAnalystEngine(Engine):
    name = "ai_analyst"
    stage = 17
    depends_on = ("risk_scoring", "attack_path")

    async def run(self, ctx) -> None:
        if not ctx.config.get("ai.enabled", True):
            ctx.logger.info("AI analyst disabled")
            ctx.store._ai_summary = self._fallback_summary(ctx)  # type: ignore
            return

        from integrations.llm import build_llm

        provider = build_llm(ctx.config, ctx.logger)
        risk_by_finding = {r.subject_id: r.score for r in ctx.store.risks()
                           if r.subject_type == "finding"}
        top = sorted(
            [f for f in ctx.store.findings() if f.status == "validated"],
            key=lambda f: risk_by_finding.get(f.id, 0), reverse=True,
        )[: ctx.config.get("ai.max_findings", 25)]

        # AI Research Analyst: structured investigation intelligence (offline).
        ctx.store._ai_research = self._research(ctx)  # type: ignore[attr-defined]

        if provider.available:
            ctx.logger.info("AI analyst using provider: %s", provider.active_name)
            ok = await self._annotate_with_llm(ctx, provider, top)
            if ok:
                try:
                    ctx.store._ai_summary = await self._summary_with_llm(  # type: ignore
                        ctx, provider)
                except Exception as exc:  # noqa: BLE001
                    ctx.logger.debug("AI summary failed: %s", exc)
                    ctx.store._ai_summary = self._fallback_summary(ctx)  # type: ignore
                ctx.bus.emit("counter", counter="ai_provider", value=0)
                return
            ctx.logger.warning("All LLM providers failed; using offline fallback")

        # Offline fallback.
        for f in top:
            f.ai = AiAnnotation(
                explanation=self._explain(f),
                prioritization=f"Risk score {risk_by_finding.get(f.id, 0)}; "
                               f"severity {f.severity.value}.",
                remediation_detail=f.remediation,
                model="offline-fallback", evidence_hash=self._ehash(f))
            ctx.store.add(f)
        ctx.store._ai_summary = self._fallback_summary(ctx)  # type: ignore
        ctx.logger.info("AI analyst: offline fallback annotations applied")

    # ---- LLM path --------------------------------------------------------
    async def _annotate_with_llm(self, ctx, provider, findings) -> bool:
        any_ok = False
        for f in findings:
            prompt = (
                "Given this finding's structured evidence, return ONLY a compact "
                "JSON object with keys: explanation, prioritization, "
                "remediation_detail, fp_assessment.\n"
                + json.dumps(self._bundle(f)))
            try:
                text = await provider.complete(_SYSTEM, prompt, max_tokens=400)
            except Exception as exc:  # noqa: BLE001
                ctx.logger.debug("LLM annotate failed: %s", exc)
                return any_ok
            data = self._safe_json(text)
            f.ai = AiAnnotation(
                explanation=data.get("explanation") or text[:400],
                prioritization=data.get("prioritization"),
                remediation_detail=data.get("remediation_detail", f.remediation),
                fp_assessment=data.get("fp_assessment"),
                model=provider.model, evidence_hash=self._ehash(f))
            ctx.store.add(f)
            any_ok = True
        return any_ok

    async def _summary_with_llm(self, ctx, provider) -> str:
        stats = self._fallback_summary(ctx)
        prompt = ("Write a 3-sentence executive security summary from these "
                  "facts:\n" + stats)
        out = await provider.complete(_SYSTEM, prompt, max_tokens=400)
        return out.strip() or stats

    # ---- offline helpers -------------------------------------------------
    def _explain(self, f) -> str:
        ev = f.evidence[0].summary if f.evidence else "structured evidence"
        return (f"This {f.severity.value} {f.category} finding on {f.target} is "
                f"supported by {len(f.evidence)} evidence item(s) ({ev}). "
                f"{f.impact}")

    def _fallback_summary(self, ctx) -> str:
        sev_counts: dict[str, int] = {}
        for f in ctx.store.findings():
            if f.status == "validated":
                sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1
        paths = ctx.store.attack_paths()
        live = len(ctx.store.assets(status="live"))
        params = ctx.store.parameters()
        risky_params = sum(1 for p in params if p.risk in ("high", "medium"))
        groups = ctx.store.finding_groups()
        root_causes = sorted({g.root_cause for g in groups
                              if g.kind == "root_cause" and g.root_cause})
        rc = ("; ".join(root_causes[:3]) if root_causes
              else "no dominant root cause")
        mitre = getattr(ctx.store, "_mitre", {}) or {}
        scenarios = ctx.store.threat_scenarios()
        top_scenario = max(scenarios, key=lambda s: s.risk_score, default=None)
        attck = ""
        if mitre:
            tactics = ", ".join(mitre.get("tactics", [])[:5]) or "n/a"
            attck = (
                f" Mapped to MITRE ATT&CK: {len(mitre.get('techniques', []))} "
                f"techniques across {len(mitre.get('tactics', []))} tactics "
                f"({mitre.get('coverage', 0)}% tactic coverage); leading tactics: "
                f"{tactics}.")
            if top_scenario:
                attck += f" Highest-risk adversary journey: {top_scenario.narrative}"
        return (
            f"Assessment covered {live} live assets and catalogued {len(params)} "
            f"parameters ({risky_params} higher-risk). Identified "
            f"{sum(sev_counts.values())} validated findings "
            f"({sev_counts.get('critical',0)} critical, {sev_counts.get('high',0)} high, "
            f"{sev_counts.get('medium',0)} medium), organized into {len(groups)} "
            f"correlation group(s). Leading root causes: {rc}. "
            f"{len(paths)} attack path(s) were reconstructed.{attck} "
            "Prioritize critical/high findings that share a root cause or enable "
            "high-value ATT&CK tactics such as Initial Access, Credential Access, "
            "or Impact.")

    def _research(self, ctx) -> dict:
        crit = sorted(ctx.store.asset_criticality(),
                      key=lambda c: -c.attack_priority)
        interesting_assets = [{
            "host": c.host, "attack_priority": c.attack_priority, "band": c.band,
            "why": f"importance {c.importance}, exposure {c.exposure}, "
                   f"business impact {c.business_impact}"} for c in crit[:8]]

        params = ctx.store.parameters()
        interesting_parameters = [{
            "name": p.name, "category": p.category, "risk": p.risk,
            "sources": p.sources, "where": p.locations[:2]}
            for p in sorted(params, key=lambda p: (
                {"high": 0, "medium": 1, "low": 2, "info": 3}[p.risk],
                -p.confidence))[:10] if p.risk in ("high", "medium")]

        import re as _re
        admin_rx = _re.compile(r"/(admin|api|graphql|debug|internal|actuator)", _re.I)
        interesting_endpoints = [{
            "url": e.url, "status": e.status_code,
            "why": ("admin/api surface" if admin_rx.search(e.url) else "parameterized")}
            for e in ctx.store.endpoints()
            if (admin_rx.search(e.url) or e.params)][:12]

        iface = [{"url": i.url, "type": i.interface_type, "confidence": i.confidence}
                 for i in ctx.store.interface_assets()][:12]

        adv = getattr(ctx.store, "_adversary", {}) or {}
        investigation_paths = []
        for ep in adv.get("entry_points", [])[:6]:
            investigation_paths.append(
                f"Investigate {ep['title']} on {ep.get('host') or ep['target']}"
                + (f" (ATT&CK {ep['technique']})" if ep.get("technique") else ""))
        for s in adv.get("narratives", [])[:2]:
            investigation_paths.append(f"Validate adversary chain: {s}")

        return {
            "interesting_assets": interesting_assets,
            "interesting_endpoints": interesting_endpoints,
            "interesting_parameters": interesting_parameters,
            "interesting_interfaces": iface,
            "investigation_paths": investigation_paths,
            "exposure": getattr(ctx.store, "_exposure", {}).get("summary", {}),
        }

    def _ehash(self, f) -> str:
        blob = json.dumps([e.model_dump(mode="json") for e in f.evidence],
                          sort_keys=True, default=str)
        return hashlib.sha256(blob.encode()).hexdigest()[:16]

    def _bundle(self, f) -> dict:
        return {
            "title": f.title, "category": f.category, "severity": f.severity.value,
            "target": f.target, "impact": f.impact,
            "evidence": [e.summary for e in f.evidence], "cve_ids": f.cve_ids,
        }

    def _safe_json(self, text: str) -> dict:
        try:
            return json.loads(text[text.index("{"): text.rindex("}") + 1])
        except Exception:
            return {}
