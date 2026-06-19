"""AttackSurfaceGraphEngine (Stage 6): unified relationship graph."""
from __future__ import annotations

import json

import networkx as nx

from core.models import Relationship

from .base import Engine


class AttackSurfaceGraphEngine(Engine):
    name = "attack_surface_graph"
    stage = 11
    depends_on = ("vulnerability_correlation", "javascript_intelligence",
                  "api_discovery", "authentication_mapping")

    async def run(self, ctx) -> None:
        g = nx.MultiDiGraph()

        for a in ctx.store.assets(status="live"):
            g.add_node(a.id, kind="asset", label=a.host, public=True)
        for s in ctx.store.services():
            nid = f"svc:{s.id}"
            g.add_node(nid, kind="service", label=f"{s.host}:{s.port}")
            g.add_edge(s.asset_id, nid, kind="exposes")
        for t in ctx.store.technologies():
            nid = f"tech:{t.id}"
            g.add_node(nid, kind="technology", label=t.name)
            g.add_edge(t.asset_id, nid, kind="uses")
        for e in ctx.store.endpoints():
            g.add_node(e.id, kind="endpoint", label=e.url[:80],
                       public=True, is_js=e.is_js)
            g.add_edge(e.asset_id, e.id, kind="serves")
        for au in ctx.store.auth_surfaces():
            nid = f"auth:{au.id}"
            g.add_node(nid, kind="auth", label=au.kind)
            g.add_edge(au.asset_id, nid, kind="has_auth")
        for cve in ctx.store.cve_matches():
            nid = f"cve:{cve.cve_id}:{cve.asset_id}"
            g.add_node(nid, kind="cve", label=cve.cve_id, kev=cve.kev)
            g.add_edge(cve.technology_id or cve.asset_id, nid, kind="vulnerable_to")
        for f in ctx.store.findings():
            if f.status != "validated":
                continue
            g.add_node(f.id, kind="finding", label=f.title[:60],
                       severity=f.severity.value)
            anchor = f.asset_id or f.target
            if anchor:
                g.add_edge(anchor, f.id, kind="has_finding")

        # Persist relationships derived from the graph.
        for u, v, data in g.edges(data=True):
            ctx.store.add(Relationship(
                src_id=str(u), src_type=g.nodes[u].get("kind", "node"),
                dst_id=str(v), dst_type=g.nodes[v].get("kind", "node"),
                kind=data.get("kind", "rel")))

        # Centrality / exposure metrics -> saved for risk + reporting.
        try:
            centrality = nx.degree_centrality(g)
        except Exception:
            centrality = {}
        self._graph = g
        self._centrality = centrality

        out = ctx.artifacts_dir / "attack_surface_graph.json"
        out.write_text(json.dumps({
            "nodes": [{"id": n, **g.nodes[n]} for n in g.nodes],
            "edges": [{"src": u, "dst": v, **d} for u, v, d in g.edges(data=True)],
        }, default=str), encoding="utf-8")

        # Stash on context for downstream engines.
        ctx.store._graph = g  # type: ignore[attr-defined]
        ctx.store._centrality = centrality  # type: ignore[attr-defined]
        ctx.logger.info("Surface graph: %d nodes, %d edges",
                        g.number_of_nodes(), g.number_of_edges())
