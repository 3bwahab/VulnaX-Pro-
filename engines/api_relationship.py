"""ApiRelationshipEngine (Stage 15): map relationships between APIs.

Builds authentication dependencies, service groupings, and token flows into an
API architecture / trust graph. Additive: emits Relationship records + a graph
artifact; does not modify ApiDiscovery.
"""
from __future__ import annotations

import json
from urllib.parse import urlparse

import networkx as nx

from core.models import Relationship

from .base import Engine


def _service_of(path: str) -> str:
    """Derive a service grouping from an API path/url (host + first segment)."""
    p = urlparse(path if path.startswith("http") else "http://x" + path)
    seg = [s for s in p.path.split("/") if s][:2]
    base = p.netloc or ""
    # collapse /api/v1/... -> api group
    key = next((s for s in seg if s not in ("api", "v1", "v2", "v3", "rest")),
               seg[0] if seg else "root")
    return f"{base}/{key}" if base else key


class ApiRelationshipEngine(Engine):
    name = "api_relationship"
    stage = 15
    depends_on = ("api_discovery", "authentication_mapping")

    async def run(self, ctx) -> None:
        apis = ctx.store.api_endpoints()
        auth_by_asset: dict[str, list] = {}
        for au in ctx.store.auth_surfaces():
            auth_by_asset.setdefault(au.asset_id, []).append(au)

        g = nx.DiGraph()
        services: dict[str, list] = {}
        for api in apis:
            svc = _service_of(api.path)
            services.setdefault(svc, []).append(api)
            g.add_node(f"api:{api.id}", kind="api", label=api.path[:60],
                       type=api.type, auth=bool(api.auth_required))
            g.add_node(f"svc:{svc}", kind="service", label=svc)
            g.add_edge(f"svc:{svc}", f"api:{api.id}", kind="part_of_service")
            ctx.store.add(Relationship(src_id=svc, src_type="api_service",
                          dst_id=api.id, dst_type="api", kind="part_of_service"))

            # Authentication dependency.
            if api.auth_required:
                for au in auth_by_asset.get(api.asset_id, []):
                    g.add_node(f"auth:{au.id}", kind="auth", label=au.kind)
                    g.add_edge(f"api:{api.id}", f"auth:{au.id}", kind="requires_auth")
                    ctx.store.add(Relationship(src_id=api.id, src_type="api",
                                  dst_id=au.id, dst_type="auth", kind="requires_auth"))

        # Token flows: auth/login surfaces -> protected APIs on the same asset.
        for asset_id, auths in auth_by_asset.items():
            issuers = [a for a in auths if a.kind in ("login", "oauth2", "saml")]
            protected = [a for a in apis
                         if a.asset_id == asset_id and a.auth_required]
            for iss in issuers:
                for api in protected:
                    g.add_edge(f"auth:{iss.id}", f"api:{api.id}", kind="token_for")
                    ctx.store.add(Relationship(src_id=iss.id, src_type="auth",
                                  dst_id=api.id, dst_type="api", kind="token_for"))

        ctx.store._api_graph = {  # type: ignore[attr-defined]
            "services": {k: len(v) for k, v in services.items()},
            "nodes": g.number_of_nodes(), "edges": g.number_of_edges(),
            "protected": sum(1 for a in apis if a.auth_required),
            "public": sum(1 for a in apis if a.auth_required is False),
        }
        out = ctx.artifacts_dir / "api_graph.json"
        out.write_text(json.dumps({
            "nodes": [{"id": n, **g.nodes[n]} for n in g.nodes],
            "edges": [{"src": u, "dst": v, **d} for u, v, d in g.edges(data=True)],
        }, default=str), encoding="utf-8")
        ctx.logger.info("API relationships: %d services, %d nodes, %d edges",
                        len(services), g.number_of_nodes(), g.number_of_edges())
