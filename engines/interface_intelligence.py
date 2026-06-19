"""InterfaceIntelligenceEngine (Stage 15): identify & classify notable interfaces.

Classifies admin consoles, dev portals, login pages, dashboards, and well-known
products (Jenkins/Grafana/Kibana/GitLab/WordPress/phpMyAdmin...) from titles, tech,
paths, and headers. Optionally captures screenshots via gowitness if installed
(otherwise classification-only). This is the "screenshot intelligence" capability.
"""
from __future__ import annotations

import re

from core.confidence import ConfidenceSignals, score_confidence
from core.models import Evidence, Finding, InterfaceAsset, Severity
from integrations.base import Capability, ToolRequest

from .base import Engine

# interface_type -> (title/url/tech regex, notable?)
_SIGNATURES: list[tuple[str, re.Pattern, bool]] = [
    ("jenkins", re.compile(r"jenkins|/job/|hudson", re.I), True),
    ("grafana", re.compile(r"grafana", re.I), True),
    ("kibana", re.compile(r"kibana|/app/kibana", re.I), True),
    ("gitlab", re.compile(r"gitlab", re.I), True),
    ("phpmyadmin", re.compile(r"phpmyadmin", re.I), True),
    ("adminer", re.compile(r"adminer", re.I), True),
    ("wordpress_admin", re.compile(r"/wp-admin|/wp-login", re.I), True),
    ("argocd", re.compile(r"argo\s*cd|argocd", re.I), True),
    ("kubernetes_dashboard", re.compile(r"kubernetes dashboard|/api/v1/namespaces",
                                        re.I), True),
    ("cloud_console", re.compile(r"console\.(aws|cloud\.google|azure)", re.I), True),
    ("swagger_ui", re.compile(r"swagger|/api-docs|openapi", re.I), False),
    ("admin_panel", re.compile(r"/admin(?:istrator)?(?:/|\b)|adminpanel", re.I), True),
    ("dashboard", re.compile(r"dashboard", re.I), False),
    ("login", re.compile(r"login|sign[\s-]?in|sso", re.I), False),
    ("dev_portal", re.compile(r"developer|portal", re.I), False),
    ("docs", re.compile(r"documentation|/docs(?:/|\b)|readme", re.I), False),
]


class InterfaceIntelligenceEngine(Engine):
    name = "interface_intelligence"
    stage = 15
    depends_on = ("deep_crawler", "technology_detection")

    async def run(self, ctx) -> None:
        tech_by_asset: dict[str, str] = {}
        for t in ctx.store.technologies():
            tech_by_asset.setdefault(t.asset_id, "")
            tech_by_asset[t.asset_id] += " " + t.name.lower()

        notable_urls: list[str] = []
        seen: set[str] = set()
        for ep in ctx.store.endpoints():
            if ep.status_code not in (200, 401, 403, None):
                continue
            hay = f"{ep.url} {ep.title or ''} {tech_by_asset.get(ep.asset_id, '')}"
            for itype, rx, notable in _SIGNATURES:
                if rx.search(hay):
                    if ep.url in seen:
                        continue
                    seen.add(ep.url)
                    conf = 0.7 if rx.search(ep.title or "") else 0.55
                    iface = InterfaceAsset(
                        asset_id=ep.asset_id, url=ep.url, interface_type=itype,
                        confidence=conf, title=ep.title,
                        evidence=f"Matched {itype} signature")
                    ctx.store.add(iface)
                    if notable:
                        notable_urls.append(ep.url)
                        self._emit_finding(ctx, ep, itype, conf)
                    break

        # Optional screenshot capture (gowitness) when available.
        cap = next(iter(ctx.adapters.available(Capability.SCREENSHOT)), None)
        if cap and notable_urls:
            shot_dir = ctx.artifacts_dir / "screenshots"
            shot_dir.mkdir(parents=True, exist_ok=True)
            in_scope = [u for u in notable_urls if ctx.in_scope(u)][:30]
            try:
                await cap.run(ToolRequest(targets=in_scope,
                              options={"outdir": str(shot_dir)}, timeout_s=180))
                ctx.logger.info("Captured screenshots for %d interfaces",
                                len(in_scope))
            except Exception as exc:  # noqa: BLE001
                ctx.logger.debug("screenshot capture failed: %s", exc)

        n = ctx.store.count(InterfaceAsset) if hasattr(ctx.store, "count") else 0
        ctx.bus._counters["interfaces"] = n
        ctx.bus.emit("counter", counter="interfaces", value=n)
        ctx.logger.info("Interface intelligence: %d interfaces classified", n)

    def _emit_finding(self, ctx, ep, itype, conf) -> None:
        sev = Severity.MEDIUM if itype in (
            "jenkins", "grafana", "kibana", "gitlab", "phpmyadmin", "adminer",
            "kubernetes_dashboard", "argocd", "cloud_console") else Severity.LOW
        f = Finding(
            title=f"Exposed {itype.replace('_', ' ')} interface",
            category="exposure", asset_id=ep.asset_id, target=ep.url, severity=sev,
            confidence=score_confidence(ConfidenceSignals(base=conf, evidence_count=1)),
            evidence=[Evidence(kind="http_response",
                      summary=f"{itype} interface reachable (HTTP {ep.status_code})",
                      data={"title": ep.title}, source=ctx.source("interface_intel"),
                      weight=conf)],
            impact="Management/developer interface exposed to the internet.",
            remediation="Restrict access (network ACL/VPN/SSO) and patch the product.",
            cwe="CWE-284", detected_by=["interface_intelligence"])
        ctx.store.add(f)
        ctx.bus.incr("findings")
