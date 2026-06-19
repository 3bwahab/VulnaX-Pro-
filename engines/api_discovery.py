"""ApiDiscoveryEngine (Stage 4): identify and characterize APIs."""
from __future__ import annotations

import json

from core.models import ApiEndpoint, Endpoint
from utils.http import HttpClient

from .base import Engine

_REST_HINTS = ("/api/", "/api", "/v1/", "/v2/", "/rest/", "/json")
_SPEC_PATHS = ["/swagger.json", "/openapi.json", "/v2/api-docs", "/v3/api-docs",
               "/api-docs", "/swagger/v1/swagger.json"]
_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphiql"]


class ApiDiscoveryEngine(Engine):
    name = "api_discovery"
    stage = 4
    depends_on = ("deep_crawler",)

    async def run(self, ctx) -> None:
        endpoints = ctx.store.endpoints()
        # Classify existing endpoints.
        for ep in endpoints:
            low = ep.url.lower()
            if any(h in low for h in _REST_HINTS) or (
                ep.content_type and "json" in ep.content_type
            ):
                ctx.store.add(ApiEndpoint(
                    asset_id=ep.asset_id, type="rest", path=ep.url,
                    method=ep.method, params=ep.params))

        live = ctx.store.assets(status="live")
        async with HttpClient(ctx) as http:
            async def probe(asset) -> None:
                # OpenAPI / Swagger specs.
                for path in _SPEC_PATHS:
                    url = f"https://{asset.host}{path}"
                    if not ctx.in_scope(url):
                        continue
                    resp = await http.fetch(url, host=asset.host)
                    if resp.ok and resp.status == 200 and "json" in resp.headers.get(
                            "content-type", ""):
                        n = self._parse_openapi(ctx, asset, url, resp.text)
                        ctx.logger.info("OpenAPI spec at %s (%d ops)", url, n)
                # GraphQL.
                for path in _GRAPHQL_PATHS:
                    url = f"https://{asset.host}{path}"
                    if not ctx.in_scope(url):
                        continue
                    resp = await http.fetch(url, host=asset.host)
                    if resp.ok and resp.status in (200, 400, 405):
                        ctx.store.add(ApiEndpoint(
                            asset_id=asset.id, type="graphql", path=url,
                            auth_required=resp.status in (401, 403)))

            await ctx.scheduler.map("http", probe, live)

        n = ctx.store.count(ApiEndpoint)
        ctx.bus._counters["api_endpoints"] = n
        ctx.bus.emit("counter", counter="api_endpoints", value=n)
        ctx.logger.info("API discovery: %d API endpoints", n)

    def _parse_openapi(self, ctx, asset, url, text) -> int:
        try:
            spec = json.loads(text)
        except Exception:
            return 0
        n = 0
        for path, ops in (spec.get("paths") or {}).items():
            for method in (ops or {}):
                if method.lower() in ("get", "post", "put", "delete", "patch"):
                    ctx.store.add(ApiEndpoint(
                        asset_id=asset.id, type="rest", path=path,
                        method=method.upper(), schema_ref=url))
                    n += 1
        return n
