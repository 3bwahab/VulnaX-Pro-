"""ConfigurationAssessmentEngine (Stage 5): misconfig & exposure checks (read-only)."""
from __future__ import annotations

from core.models import Confidence, Evidence, Finding, Severity
from utils.http import HttpClient

from .base import Engine

SECURITY_HEADERS = {
    "strict-transport-security": ("Missing HSTS header", Severity.LOW, "CWE-319"),
    "content-security-policy": ("Missing Content-Security-Policy", Severity.LOW,
                                "CWE-1021"),
    "x-frame-options": ("Missing X-Frame-Options (clickjacking)", Severity.LOW,
                        "CWE-1021"),
    "x-content-type-options": ("Missing X-Content-Type-Options", Severity.INFO,
                               "CWE-693"),
}

SENSITIVE_SIGNATURES = {
    "/.git/config": ("Exposed .git repository", Severity.HIGH,
                     ["[core]", "repositoryformatversion"]),
    "/.git/HEAD": ("Exposed .git repository", Severity.HIGH, ["ref:"]),
    "/.env": ("Exposed .env file", Severity.CRITICAL,
              ["APP_KEY", "DB_PASSWORD", "SECRET", "="]),
    "/actuator/env": ("Exposed Spring actuator env", Severity.HIGH, ["propertySources"]),
    "/server-status": ("Exposed Apache server-status", Severity.MEDIUM,
                       ["Apache Server Status"]),
    "/phpinfo.php": ("Exposed phpinfo()", Severity.MEDIUM, ["PHP Version"]),
}


class ConfigurationAssessmentEngine(Engine):
    name = "configuration_assessment"
    stage = 7
    depends_on = ("technology_detection", "deep_crawler")

    async def run(self, ctx) -> None:
        live = ctx.store.assets(status="live")
        async with HttpClient(ctx) as http:
            async def assess(asset) -> None:
                base = f"https://{asset.host}"
                resp = await http.fetch(base, host=asset.host)
                if resp.ok and resp.status:
                    self._check_headers(ctx, asset, base, resp.headers)
                    self._check_cors(ctx, asset, base, resp.headers)
                await self._check_sensitive(ctx, http, asset)

            await ctx.scheduler.map("http", assess, live)

        ctx.logger.info("Config assessment complete")

    def _check_headers(self, ctx, asset, base, headers) -> None:
        for hname, (title, sev, cwe) in SECURITY_HEADERS.items():
            if hname not in headers:
                ctx.store.add(Finding(
                    title=title, category="misconfig", asset_id=asset.id,
                    target=base, severity=sev,
                    confidence=Confidence(score=0.9, rationale="header absent",
                                          signals=1),
                    evidence=[Evidence(kind="header", summary=f"{hname} not set",
                                       data={"header": hname},
                                       source=ctx.source("config"), weight=0.9)],
                    impact="Weakens browser-side defenses.",
                    remediation=f"Add the {hname} response header.",
                    cwe=cwe, detected_by=["configuration_assessment"]))
                ctx.bus.incr("findings")

    def _check_cors(self, ctx, asset, base, headers) -> None:
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "")
        if acao == "*" and acac.lower() == "true":
            ctx.store.add(Finding(
                title="Insecure CORS: wildcard origin with credentials",
                category="misconfig", asset_id=asset.id, target=base,
                severity=Severity.HIGH,
                confidence=Confidence(score=0.85, rationale="CORS headers", signals=2),
                evidence=[Evidence(kind="header",
                          summary="ACAO=* with ACAC=true",
                          data={"acao": acao, "acac": acac},
                          source=ctx.source("config"), weight=0.85)],
                impact="Cross-origin credentialed requests can read responses.",
                remediation="Reflect specific trusted origins; never use * with credentials.",
                cwe="CWE-942", detected_by=["configuration_assessment"]))
            ctx.bus.incr("findings")

    async def _check_sensitive(self, ctx, http, asset) -> None:
        for path, (title, sev, sigs) in SENSITIVE_SIGNATURES.items():
            url = f"https://{asset.host}{path}"
            if not ctx.in_scope(url):
                continue
            resp = await http.fetch(url, host=asset.host)
            if resp.ok and resp.status == 200 and resp.text:
                if any(s in resp.text for s in sigs):
                    f = Finding(
                        title=title, category="exposure", asset_id=asset.id,
                        target=url, severity=sev,
                        confidence=Confidence(score=0.95,
                                              rationale="content signature match",
                                              signals=2),
                        evidence=[Evidence(kind="http_response",
                                  summary=f"200 OK with sensitive signature at {path}",
                                  data={"snippet": resp.text[:120]},
                                  source=ctx.source("config"), weight=0.95)],
                        impact="Exposed sensitive data / source / configuration.",
                        remediation=f"Block public access to {path}.",
                        cwe="CWE-538", detected_by=["configuration_assessment"])
                    ctx.store.add(f)
                    ctx.bus.incr("findings")
                    ctx.bus.emit("top_finding", title=title, severity=sev.value)
