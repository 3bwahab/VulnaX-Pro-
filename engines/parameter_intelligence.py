"""ParameterIntelligenceEngine V2 (Stage 5): unified parameter inventory + graph.

Collects parameters from URLs, query strings, forms, JavaScript, OpenAPI/Swagger,
GraphQL, and API responses; classifies them by purpose and risk; builds the
parameter graph (param -> endpoint relationships).
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urlparse

from core.models import Parameter, Relationship

from .base import Engine

# Classification by name keyword -> (category, risk). First match wins (ordered).
_CLASSIFY: list[tuple[set[str], str, str]] = [
    ({"redirect", "redir", "url", "next", "return", "returnurl", "returnto",
      "dest", "destination", "continue", "goto", "callback", "link", "out",
      "forward", "to"}, "redirect", "high"),
    ({"file", "filename", "filepath", "path", "dir", "folder", "download",
      "upload", "doc", "document", "attachment", "load", "include", "page_path",
      "template_path"}, "file_handling", "high"),
    ({"template", "tpl", "view", "theme", "layout", "render", "tmpl"},
     "template", "high"),
    ({"token", "auth", "session", "sessionid", "jwt", "apikey", "api_key",
      "password", "passwd", "pwd", "otp", "mfa", "credential", "secret",
      "access_token", "refresh_token"}, "authentication", "high"),
    ({"role", "roles", "scope", "scopes", "permission", "permissions",
      "is_admin", "isadmin", "privilege", "grant", "acl", "group", "level"},
     "authorization", "high"),
    ({"admin", "debug", "test", "internal", "config", "setup", "install",
      "maintenance", "superuser"}, "administrative", "high"),
    ({"id", "uid", "uuid", "user_id", "userid", "account_id", "order_id",
      "doc_id", "file_id", "pid", "gid", "object", "ref", "item", "record"},
     "object_reference", "high"),
    ({"q", "query", "search", "term", "keyword", "keywords", "s", "find"},
     "search", "medium"),
    ({"format", "output", "type", "mode", "action", "method", "op", "cmd",
      "func", "function", "do", "call"}, "api_control", "medium"),
    ({"filter", "sort", "order", "orderby", "sort_by", "field", "fields",
      "where", "status", "category", "tag", "select"}, "filtering", "medium"),
    ({"page", "limit", "offset", "per_page", "perpage", "size", "count",
      "start", "end", "from", "skip", "take", "cursor"}, "pagination", "low"),
]


def _classify(name: str) -> tuple[str, str]:
    low = name.lower()
    for names, category, risk in _CLASSIFY:
        if low in names:
            return category, risk
    # substring fallback for compound names (e.g. "redirect_uri").
    for names, category, risk in _CLASSIFY:
        if any(n in low for n in names if len(n) > 3):
            return category, risk
    return "unknown", "info"


class ParameterIntelligenceEngine(Engine):
    name = "parameter_intelligence"
    stage = 5
    depends_on = ("deep_crawler", "javascript_intelligence", "api_discovery")

    async def run(self, ctx) -> None:
        # name -> aggregation dict
        agg: dict[str, dict] = {}

        def record(name, asset_id, source, location, method=None, value=None):
            if not name:
                return
            key = (asset_id, name.lower())
            slot = agg.setdefault(key, {
                "name": name, "asset_id": asset_id, "sources": set(),
                "locations": set(), "methods": set(), "values": set()})
            slot["sources"].add(source)
            if location:
                slot["locations"].add(location[:200])
            if method:
                slot["methods"].add(method)
            if value and len(str(value)) < 60:
                slot["values"].add(str(value))

        # 1) URL query strings + form params from endpoints.
        for ep in ctx.store.endpoints():
            for k, v in parse_qsl(urlparse(ep.url).query):
                record(k, ep.asset_id, "url", ep.url, ep.method, v)
            for p in ep.params:
                src = "form" if ep.source == "form" else "url"
                record(p, ep.asset_id, src, ep.url, ep.method)

        # 2) JavaScript-discovered endpoints (query keys).
        for js in ctx.store.js_assets():
            for raw in js.endpoints:
                q = urlparse(raw).query
                for k, v in parse_qsl(q):
                    record(k, js.asset_id, "js", raw, None, v)

        # 3) API endpoints (REST params, GraphQL).
        for api in ctx.store.api_endpoints():
            for p in api.params:
                src = "graphql" if api.type == "graphql" else "openapi"
                record(p, api.asset_id, src, api.path, api.method)

        # Materialize Parameter records + parameter graph edges.
        count = 0
        for (asset_id, _low), slot in agg.items():
            category, risk = _classify(slot["name"])
            sources = sorted(slot["sources"])
            locations = sorted(slot["locations"])
            confidence = min(0.95, 0.4 + 0.1 * len(sources) + 0.05 * min(
                len(locations), 6))
            param = Parameter(
                asset_id=asset_id, name=slot["name"], category=category,
                risk=risk, confidence=round(confidence, 2), sources=sources,
                locations=locations[:25], methods=sorted(slot["methods"]),
                sample_values=sorted(slot["values"])[:5],
                context=f"Seen via {', '.join(sources)} on {len(locations)} location(s)")
            ctx.store.add(param)
            count += 1
            # Parameter graph: param -> endpoint.
            for loc in locations[:25]:
                ctx.store.add(Relationship(
                    src_id=param.id, src_type="parameter",
                    dst_id=loc, dst_type="endpoint", kind="param_of"))

        risky = sum(1 for p in ctx.store.parameters() if p.risk in ("high", "medium"))
        ctx.bus._counters["parameters"] = count
        ctx.bus.emit("counter", counter="parameters", value=count)
        ctx.logger.info("Parameter intelligence: %d params (%d high/medium risk)",
                        count, risky)
