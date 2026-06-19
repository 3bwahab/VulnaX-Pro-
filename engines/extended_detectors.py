"""ExtendedDetectorEngine (Stage 7): broad, evidence-backed passive coverage.

Adds detection for the expanded vulnerability list WITHOUT active exploitation:
artifacts/config/secret exposure, directory listing, admin & debug interfaces,
info disclosure, TLS issues, GraphQL introspection, JWT weaknesses, container/k8s
exposure, and parameter-based indicators (open redirect / SSRF / SSTI / LFI /
IDOR / deserialization). Active payload injection lives in validation_orchestration.
"""
from __future__ import annotations

import asyncio
import base64
import json
import re
import socket
import ssl
from datetime import datetime, timezone

from core.confidence import ConfidenceSignals, score_confidence
from core.models import Evidence, Finding, Severity
from utils.http import HttpClient

from .base import Engine

# path -> (title, severity, [content signatures], category, cwe)
ARTIFACT_SIGNATURES: dict[str, tuple] = {
    "/.git/config": ("Exposed Git repository", Severity.HIGH,
                     ["[core]", "repositoryformatversion"], "dev_artifact", "CWE-538"),
    "/.svn/entries": ("Exposed SVN metadata", Severity.MEDIUM, ["dir", "\n"],
                      "dev_artifact", "CWE-538"),
    "/.hg/requires": ("Exposed Mercurial metadata", Severity.MEDIUM, ["revlog"],
                      "dev_artifact", "CWE-538"),
    "/.env": ("Exposed environment file", Severity.CRITICAL,
              ["APP_KEY", "DB_PASSWORD", "SECRET", "API_KEY", "="], "config", "CWE-538"),
    "/config.json": ("Exposed config.json", Severity.MEDIUM,
                     ["password", "secret", "apiKey", "token"], "config", "CWE-538"),
    "/.npmrc": ("Exposed .npmrc", Severity.HIGH, ["_authToken", "registry"],
                "config", "CWE-538"),
    "/composer.json": ("Exposed composer.json", Severity.LOW, ["require", "name"],
                       "dev_artifact", "CWE-200"),
    "/package.json": ("Exposed package.json", Severity.LOW,
                      ["dependencies", "version"], "dev_artifact", "CWE-200"),
    "/Dockerfile": ("Exposed Dockerfile", Severity.LOW, ["FROM ", "RUN "],
                    "dev_artifact", "CWE-200"),
    "/docker-compose.yml": ("Exposed docker-compose.yml", Severity.MEDIUM,
                            ["services:", "image:"], "config", "CWE-538"),
    "/.gitlab-ci.yml": ("Exposed CI config", Severity.LOW, ["stages:", "script:"],
                        "config", "CWE-200"),
    "/backup.zip": ("Exposed backup archive", Severity.HIGH, ["PK"], "backup",
                    "CWE-538"),
    "/backup.sql": ("Exposed SQL dump", Severity.HIGH,
                    ["INSERT INTO", "CREATE TABLE"], "backup", "CWE-538"),
    "/.DS_Store": ("Exposed .DS_Store", Severity.LOW, ["Bud1", "\x00"], "dev_artifact",
                   "CWE-200"),
    "/debug": ("Debug endpoint exposed", Severity.MEDIUM, ["debug", "trace"],
               "debug", "CWE-489"),
    "/_profiler": ("Symfony profiler exposed", Severity.HIGH, ["Profiler", "Symfony"],
                   "debug", "CWE-489"),
    "/debug/pprof/": ("Go pprof debug exposed", Severity.MEDIUM, ["profiles", "goroutine"],
                      "debug", "CWE-489"),
    "/metrics": ("Prometheus metrics exposed", Severity.LOW,
                 ["# HELP", "# TYPE", "process_cpu"], "container", "CWE-200"),
    "/v2/_catalog": ("Docker registry catalog exposed", Severity.HIGH,
                     ["repositories"], "container", "CWE-538"),
    "/api/v1/namespaces": ("Kubernetes API exposed", Severity.CRITICAL,
                           ["NamespaceList", "kind"], "kubernetes", "CWE-538"),
    "/.well-known/security.txt": ("security.txt present", Severity.INFO,
                                  ["Contact"], "info", None),
}

_INFO_DISCLOSURE = {
    "stack_trace": re.compile(r"(Traceback \(most recent call last\)|"
                              r"Exception in thread|at [a-zA-Z0-9_.]+\([A-Za-z]+\.java:"
                              r"|System\.Web\.|\.cs:line \d+)"),
    "sql_error": re.compile(r"(SQL syntax.*MySQL|Warning.*mysqli|"
                            r"PostgreSQL.*ERROR|ORA-\d{5}|SQLite3::)"),
    "internal_ip": re.compile(r"\b(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|"
                              r"172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)\b"),
    "debug_banner": re.compile(r"(Werkzeug Debugger|Whoops\\|Laravel Ignition|"
                               r"DEBUG = True|Django Version|Whitelabel Error Page)"),
}

# parameter category -> (indicator title, severity, cwe, impact)
_PARAM_INDICATORS = {
    "redirect": ("Open redirect candidate parameter", Severity.MEDIUM, "CWE-601",
                 "Parameter may control redirect destination."),
    "file_handling": ("Path traversal / file inclusion candidate parameter",
                      Severity.MEDIUM, "CWE-22",
                      "Parameter may reference server-side files."),
    "template": ("Template injection candidate parameter", Severity.MEDIUM, "CWE-1336",
                 "Parameter may flow into a template engine."),
    "object_reference": ("IDOR / access-control candidate parameter", Severity.MEDIUM,
                         "CWE-639", "Parameter references an object id."),
    "api_control": ("SSRF / command candidate parameter", Severity.LOW, "CWE-918",
                    "Parameter may control server-side actions/URLs."),
}


class ExtendedDetectorEngine(Engine):
    name = "extended_detectors"
    stage = 7
    depends_on = ("parameter_intelligence", "assessment_planner")

    async def run(self, ctx) -> None:
        live = ctx.store.assets(status="live")
        async with HttpClient(ctx) as http:
            async def assess(asset) -> None:
                await self._artifacts(ctx, http, asset)
                await self._info_disclosure(ctx, http, asset)
                await self._tls(ctx, asset)
                self._admin_interfaces(ctx, asset)
            await ctx.scheduler.map("http", assess, live)
            await self._graphql_introspection(ctx, http)

        self._param_indicators(ctx)
        self._jwt_and_cookies(ctx)
        self._enum_ratelimit_indicators(ctx)
        ctx.logger.info("Extended detectors complete")

    # ---- helpers ---------------------------------------------------------
    def _emit(self, ctx, **kw) -> None:
        f = Finding(**kw)
        if not f.evidence:
            return  # invariant: no finding without evidence
        ctx.store.add(f)
        ctx.bus.incr("findings")
        if f.severity.rank >= Severity.HIGH.rank:
            ctx.bus.emit("top_finding", title=f.title, severity=f.severity.value)

    async def _artifacts(self, ctx, http, asset) -> None:
        for path, (title, sev, sigs, cat, cwe) in ARTIFACT_SIGNATURES.items():
            url = f"https://{asset.host}{path}"
            if not ctx.in_scope(url):
                continue
            resp = await http.fetch(url, host=asset.host)
            if not resp.ok or resp.status != 200 or not resp.text:
                continue
            body = resp.text
            if not any(s in body for s in sigs):
                continue
            # Directory listing flavor.
            conf = score_confidence(ConfidenceSignals(
                base=0.85, evidence_count=2, fingerprint_match=True))
            self._emit(
                ctx, title=title, category="exposure", asset_id=asset.id, target=url,
                severity=sev, confidence=conf,
                evidence=[Evidence(kind="http_response",
                          summary=f"200 OK with signature at {path}",
                          data={"snippet": body[:160]}, source=ctx.source("extended"),
                          weight=0.85)],
                impact="Sensitive artifact/configuration is publicly accessible.",
                remediation=f"Block public access to {path}.",
                cwe=cwe, detected_by=["extended_detectors"])

        # Directory listing on directory-like crawled endpoints (sampled).
        dirs = [e for e in ctx.store.endpoints()
                if e.asset_id == asset.id and e.url.rstrip("/").count("/") <= 4
                and e.url.endswith("/")][:8]
        for ep in dirs:
            resp = await http.fetch(ep.url, host=asset.host)
            if resp.ok and resp.status == 200 and re.search(
                    r"<title>Index of /|Directory listing for", resp.text or ""):
                conf = score_confidence(ConfidenceSignals(base=0.9, evidence_count=1,
                                                          fingerprint_match=True))
                self._emit(
                    ctx, title="Directory listing enabled", category="exposure",
                    asset_id=asset.id, target=ep.url, severity=Severity.MEDIUM,
                    confidence=conf,
                    evidence=[Evidence(kind="http_response",
                              summary="Auto-generated index page", data={},
                              source=ctx.source("extended"), weight=0.9)],
                    impact="Enumerable files may reveal sensitive content.",
                    remediation="Disable autoindex / directory listing.",
                    cwe="CWE-548", detected_by=["extended_detectors"])

    async def _info_disclosure(self, ctx, http, asset) -> None:
        resp = await http.fetch(f"https://{asset.host}", host=asset.host)
        if not resp.ok or not resp.text:
            return
        for kind, rx in _INFO_DISCLOSURE.items():
            m = rx.search(resp.text)
            if m:
                sev = Severity.MEDIUM if kind in ("stack_trace", "sql_error",
                                                  "debug_banner") else Severity.LOW
                conf = score_confidence(ConfidenceSignals(base=0.7, evidence_count=1))
                self._emit(
                    ctx, title=f"Information disclosure ({kind})", category="exposure",
                    asset_id=asset.id, target=f"https://{asset.host}", severity=sev,
                    confidence=conf,
                    evidence=[Evidence(kind="http_response",
                              summary=f"{kind} pattern in response",
                              data={"match": m.group(0)[:80]},
                              source=ctx.source("extended"), weight=0.7)],
                    impact="Leaked internal details aid an attacker.",
                    remediation="Suppress verbose errors/banners in production.",
                    cwe="CWE-200", detected_by=["extended_detectors"])

    async def _tls(self, ctx, asset) -> None:
        info = await _inspect_tls(asset.host)
        if not info:
            return
        proto, not_after = info
        if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
            conf = score_confidence(ConfidenceSignals(base=0.9, evidence_count=1,
                                                      fingerprint_match=True))
            self._emit(
                ctx, title=f"Weak TLS protocol supported ({proto})",
                category="misconfig", asset_id=asset.id,
                target=f"https://{asset.host}", severity=Severity.MEDIUM, confidence=conf,
                evidence=[Evidence(kind="behavioral", summary=f"Negotiated {proto}",
                          data={"protocol": proto}, source=ctx.source("extended"),
                          weight=0.9)],
                impact="Deprecated TLS is vulnerable to known attacks.",
                remediation="Disable TLS < 1.2.", cwe="CWE-326",
                detected_by=["extended_detectors"])
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc)
                days = (exp - datetime.now(timezone.utc)).days
                if days < 14:
                    sev = Severity.MEDIUM if days >= 0 else Severity.HIGH
                    conf = score_confidence(ConfidenceSignals(base=0.95,
                                                              evidence_count=1))
                    self._emit(
                        ctx, title=("Expired TLS certificate" if days < 0
                                    else "TLS certificate expiring soon"),
                        category="misconfig", asset_id=asset.id,
                        target=f"https://{asset.host}", severity=sev, confidence=conf,
                        evidence=[Evidence(kind="behavioral",
                                  summary=f"Certificate not_after={not_after} ({days}d)",
                                  data={"days": days}, source=ctx.source("extended"),
                                  weight=0.95)],
                        impact="Expired/expiring certificate breaks trust.",
                        remediation="Renew the TLS certificate.", cwe="CWE-298",
                        detected_by=["extended_detectors"])
            except Exception:
                pass

    def _admin_interfaces(self, ctx, asset) -> None:
        rx = re.compile(r"/(admin|administrator|wp-admin|manage|console|dashboard|"
                        r"phpmyadmin|adminer|portal|cpanel)(/|$)", re.I)
        for ep in ctx.store.endpoints():
            if ep.asset_id != asset.id or ep.status_code not in (200, 401, 403):
                continue
            if rx.search(ep.url):
                sev = Severity.MEDIUM if ep.status_code == 200 else Severity.LOW
                conf = score_confidence(ConfidenceSignals(base=0.7, evidence_count=1))
                self._emit(
                    ctx, title="Exposed administrative interface", category="exposure",
                    asset_id=asset.id, target=ep.url, severity=sev, confidence=conf,
                    evidence=[Evidence(kind="http_response",
                              summary=f"Admin path reachable (HTTP {ep.status_code})",
                              data={"status": ep.status_code},
                              source=ctx.source("extended"), weight=0.7)],
                    impact="Admin surface exposed to the internet.",
                    remediation="Restrict admin interfaces by network/auth.",
                    cwe="CWE-284", detected_by=["extended_detectors"])

    async def _graphql_introspection(self, ctx, http) -> None:
        gql = [a for a in ctx.store.api_endpoints() if a.type == "graphql"]
        query = {"query": "{__schema{queryType{name}}}"}
        for api in gql:
            if not ctx.in_scope(api.path):
                continue
            try:
                resp = await http._client.post(  # read-only introspection probe
                    api.path, json=query,
                    headers={"Content-Type": "application/json"})
                if resp.status_code == 200 and "__schema" in resp.text:
                    conf = score_confidence(ConfidenceSignals(
                        base=0.9, evidence_count=1, fingerprint_match=True))
                    self._emit(
                        ctx, title="GraphQL introspection enabled", category="misconfig",
                        asset_id=api.asset_id, target=api.path, severity=Severity.MEDIUM,
                        confidence=conf,
                        evidence=[Evidence(kind="behavioral",
                                  summary="Introspection query returned __schema",
                                  data={}, source=ctx.source("extended"), weight=0.9)],
                        impact="Full API schema is disclosed to attackers.",
                        remediation="Disable introspection in production.",
                        cwe="CWE-200", detected_by=["extended_detectors"])
            except Exception:
                continue

    def _param_indicators(self, ctx) -> None:
        for p in ctx.store.parameters():
            spec = _PARAM_INDICATORS.get(p.category)
            if not spec:
                continue
            title, sev, cwe, impact = spec
            conf = score_confidence(ConfidenceSignals(
                base=0.4, evidence_count=1, independent_sources=len(p.sources)))
            loc = p.locations[0] if p.locations else p.name
            self._emit(
                ctx, title=f"{title}: '{p.name}'", category="indicator",
                asset_id=p.asset_id, target=loc, severity=sev, confidence=conf,
                evidence=[Evidence(kind="behavioral",
                          summary=f"Parameter '{p.name}' classified {p.category} "
                          f"(seen via {', '.join(p.sources)})",
                          data={"locations": p.locations[:5]},
                          source=ctx.source("parameter_intelligence"), weight=0.4)],
                impact=impact + " Candidate for targeted validation (--active).",
                remediation="Validate/encode this input; enforce allow-lists.",
                cwe=cwe, status="needs_review", detected_by=["parameter_intelligence"])

    def _jwt_and_cookies(self, ctx) -> None:
        jwt_rx = re.compile(r"eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}")
        for f in ctx.store.findings():
            if "jwt" not in f.title.lower():
                continue
            for ev in f.evidence:
                tok = str(ev.data)
                m = jwt_rx.search(tok)
                if not m:
                    continue
                header = _decode_jwt_header(m.group(0))
                alg = (header or {}).get("alg", "")
                if alg.lower() == "none" or alg.upper().startswith("HS"):
                    sev = Severity.HIGH if alg.lower() == "none" else Severity.LOW
                    conf = score_confidence(ConfidenceSignals(base=0.6))
                    self._emit(
                        ctx, title=f"JWT weak algorithm ({alg or 'unknown'})",
                        category="misconfig", asset_id=f.asset_id, target=f.target,
                        severity=sev, confidence=conf,
                        evidence=[Evidence(kind="js_match",
                                  summary=f"JWT header alg={alg}", data={"alg": alg},
                                  source=ctx.source("extended"), weight=0.6)],
                        impact="Weak/none JWT signing enables token forgery.",
                        remediation="Use RS256/ES256; reject alg=none.",
                        cwe="CWE-347", detected_by=["extended_detectors"])

    def _enum_ratelimit_indicators(self, ctx) -> None:
        auths = ctx.store.auth_surfaces()
        seen_assets: set[str] = set()
        for au in auths:
            if au.kind in ("login", "oauth2") and au.asset_id not in seen_assets:
                seen_assets.add(au.asset_id)
                conf = score_confidence(ConfidenceSignals(base=0.3))
                self._emit(
                    ctx, title="Authentication surface present (enumeration / "
                    "rate-limit review)", category="indicator", asset_id=au.asset_id,
                    target=au.endpoint, severity=Severity.INFO, confidence=conf,
                    evidence=[Evidence(kind="behavioral",
                              summary=f"{au.kind} endpoint detected", data={},
                              source=ctx.source("authentication_mapping"), weight=0.3)],
                    impact="Login flows should be tested for account enumeration "
                    "and rate limiting.",
                    remediation="Enforce rate limiting and generic auth errors.",
                    cwe="CWE-307", status="needs_review",
                    detected_by=["authentication_mapping"])


# --------------------------------------------------------------------------- #
def _decode_jwt_header(token: str) -> dict | None:
    try:
        part = token.split(".")[0]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part))
    except Exception:
        return None


async def _inspect_tls(host: str, port: int = 443) -> tuple[str, str] | None:
    def _q():
        ctxs = ssl.create_default_context()
        ctxs.check_hostname = False
        ctxs.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=6) as sock:
                with ctxs.wrap_socket(sock, server_hostname=host) as ss:
                    cert = ss.getpeercert()
                    return ss.version() or "", (cert or {}).get("notAfter", "")
        except Exception:
            return None
    return await asyncio.to_thread(_q)
