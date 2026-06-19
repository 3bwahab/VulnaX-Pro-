"""JavaScriptIntelligenceEngine (Stage 4): analyze every JS file."""
from __future__ import annotations

import hashlib

from core.models import (Confidence, Endpoint, Evidence, Finding, JsAsset,
                         Severity)
from utils.http import HttpClient
from utils.net import normalize_url
from utils.text import (CLOUD_RE, GRAPHQL_RE, extract_endpoints, extract_secrets)

from .base import Engine


class JavaScriptIntelligenceEngine(Engine):
    name = "javascript_intelligence"
    stage = 4
    depends_on = ("deep_crawler",)

    async def run(self, ctx) -> None:
        js_endpoints = [e for e in ctx.store.endpoints() if e.is_js]
        analyzed = 0
        async with HttpClient(ctx) as http:
            async def analyze(ep: Endpoint) -> int:
                resp = await http.fetch(ep.url, host=None)
                if not resp.ok or not resp.text:
                    return 0
                self._analyze_js(ctx, ep, resp.text)
                return 1

            results = await ctx.scheduler.map("http", analyze, js_endpoints)
            analyzed = sum(results)

        ctx.bus._counters["js_files"] = analyzed
        ctx.bus.emit("counter", counter="js_files", value=analyzed)
        ctx.logger.info("JS intelligence: %d files analyzed", analyzed)

    def _analyze_js(self, ctx, ep: Endpoint, text: str) -> None:
        sha = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
        endpoints = sorted(extract_endpoints(text))
        secrets = extract_secrets(text)
        cloud = sorted(set(CLOUD_RE.findall(text)))
        graphql = bool(GRAPHQL_RE.search(text))
        has_map = "//# sourceMappingURL=" in text

        js = JsAsset(
            asset_id=ep.asset_id, url=ep.url, sha256=sha, size=len(text),
            endpoints=endpoints[:200], cloud_refs=cloud,
            graphql_refs=["graphql"] if graphql else [], has_sourcemap=has_map)
        ctx.store.add(js)

        # Register discovered endpoints.
        for path in endpoints[:200]:
            url = path if path.startswith("http") else self._absolutize(ep.url, path)
            if url and ctx.in_scope(url):
                ctx.store.add(Endpoint(
                    asset_id=ep.asset_id, url=normalize_url(url), source="js",
                    sources=[ctx.source("js_intel")]))

        # Secrets -> findings.
        for kind, value in secrets:
            sev = Severity.CRITICAL if kind in (
                "aws_secret_key", "private_key", "stripe_key", "aws_access_key"
            ) else Severity.HIGH
            f = Finding(
                title=f"Exposed secret in JavaScript ({kind})",
                category="secret", asset_id=ep.asset_id, target=ep.url,
                severity=sev,
                confidence=Confidence(score=0.85, rationale="pattern + context",
                                      signals=1),
                evidence=[Evidence(
                    kind="js_match",
                    summary=f"{kind} found in {ep.url}",
                    data={"redacted": value[:6] + "…", "type": kind},
                    source=ctx.source("js_intel"), weight=0.85)],
                impact="Leaked credential may grant unauthorized access.",
                remediation="Rotate the secret and remove it from client-side code.",
                cwe="CWE-200", detected_by=["javascript_intelligence"])
            ctx.store.add(f)
            ctx.bus.incr("findings")
            ctx.bus.emit("top_finding", title=f.title, severity=sev.value)

        # Cloud references -> informational findings.
        for ref in cloud:
            ctx.store.add(Finding(
                title="Cloud storage reference in JavaScript",
                category="exposure", asset_id=ep.asset_id, target=ep.url,
                severity=Severity.INFO,
                confidence=Confidence(score=0.6, rationale="regex match", signals=1),
                evidence=[Evidence(kind="js_match", summary=f"Cloud ref: {ref}",
                                   data={"ref": ref}, source=ctx.source("js_intel"),
                                   weight=0.6)],
                impact="May indicate accessible cloud storage; verify ACLs.",
                remediation="Ensure referenced buckets/containers are not public.",
                detected_by=["javascript_intelligence"]))

    def _absolutize(self, base: str, path: str) -> str | None:
        from urllib.parse import urljoin

        try:
            return urljoin(base, path)
        except Exception:
            return None
