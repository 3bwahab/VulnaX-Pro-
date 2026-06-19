"""AuthenticationMappingEngine (Stage 4): map auth & session surfaces."""
from __future__ import annotations

import re

from core.models import AuthSurface, Confidence, Endpoint, Evidence, Finding, Severity
from utils.http import HttpClient

from .base import Engine

_LOGIN_RE = re.compile(r"(login|signin|sign-in|auth|sso|account|session)", re.I)
_OAUTH_RE = re.compile(r"(oauth|/authorize|client_id=|response_type=)", re.I)
_SAML_RE = re.compile(r"(saml|SAMLRequest|/sso/saml)", re.I)


class AuthenticationMappingEngine(Engine):
    name = "authentication_mapping"
    stage = 4
    depends_on = ("deep_crawler", "api_discovery")

    async def run(self, ctx) -> None:
        live = ctx.store.assets(status="live")
        # Map auth endpoints from known endpoints.
        for ep in ctx.store.endpoints():
            kind = self._classify(ep.url)
            if kind:
                ctx.store.add(AuthSurface(
                    asset_id=ep.asset_id, kind=kind, endpoint=ep.url))

        # Inspect root cookies for session security flags.
        async with HttpClient(ctx) as http:
            async def inspect(asset) -> None:
                resp = await http.fetch(f"https://{asset.host}", host=asset.host)
                if not resp.ok:
                    return
                cookie = resp.headers.get("set-cookie", "")
                if not cookie:
                    return
                flags = {
                    "httponly": "httponly" in cookie.lower(),
                    "secure": "secure" in cookie.lower(),
                    "samesite": "samesite" in cookie.lower(),
                }
                ctx.store.add(AuthSurface(
                    asset_id=asset.id, kind="session",
                    endpoint=f"https://{asset.host}", cookie_flags=flags))
                missing = [k for k, v in flags.items() if not v]
                if missing and ("session" in cookie.lower() or "sess" in cookie.lower()):
                    ctx.store.add(Finding(
                        title=f"Session cookie missing flags: {', '.join(missing)}",
                        category="misconfig", asset_id=asset.id,
                        target=f"https://{asset.host}", severity=Severity.MEDIUM,
                        confidence=Confidence(score=0.8, rationale="Set-Cookie header",
                                              signals=1),
                        evidence=[Evidence(kind="header",
                                  summary="Set-Cookie missing security flags",
                                  data={"missing": missing},
                                  source=ctx.source("auth"), weight=0.8)],
                        impact="Session theft / CSRF risk.",
                        remediation="Set HttpOnly, Secure, and SameSite on session cookies.",
                        cwe="CWE-614", detected_by=["authentication_mapping"]))
                    ctx.bus.incr("findings")

            await ctx.scheduler.map("http", inspect, live)

        n = ctx.store.count(AuthSurface)
        ctx.logger.info("Auth mapping: %d auth surfaces", n)

    def _classify(self, url: str) -> str | None:
        if _OAUTH_RE.search(url):
            return "oauth2"
        if _SAML_RE.search(url):
            return "saml"
        if _LOGIN_RE.search(url):
            return "login"
        return None
