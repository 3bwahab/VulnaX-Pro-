"""VisualAttackSurfaceEngine (Stage 16): visual representations of the surface.

Builds a consolidated graph (assets, technologies, auth, findings, ATT&CK
techniques) and renders a self-contained SVG (deterministic spring layout, no JS
or external CDN) plus a JSON data product that can drive other views.
"""
from __future__ import annotations

import html
import json

import networkx as nx

from core.models import Severity

from .base import Engine

_SEV_COLOR = {"critical": "#b30000", "high": "#e34a33", "medium": "#fc8d59",
              "low": "#2c7fb8", "info": "#8b949e"}
_KIND_COLOR = {"asset": "#1f6feb", "technology": "#8957e5", "auth": "#d29922",
               "technique": "#2da44e", "service": "#6e7681"}


class VisualAttackSurfaceEngine(Engine):
    name = "visual_attack_surface"
    stage = 16
    depends_on = ("attack_surface_graph", "asset_criticality",
                  "mitre_intelligence")

    async def run(self, ctx) -> None:
        g = nx.Graph()
        crit_by_asset = {c.asset_id: c for c in ctx.store.asset_criticality()}
        risk_by_finding = {r.subject_id: r.score for r in ctx.store.risks()
                           if r.subject_type == "finding"}

        for a in ctx.store.assets(status="live"):
            c = crit_by_asset.get(a.id)
            g.add_node(f"asset:{a.id}", kind="asset", label=a.host,
                       weight=(c.attack_priority if c else 30))
        for t in ctx.store.technologies():
            g.add_node(f"tech:{t.id}", kind="technology", label=t.name, weight=12)
            g.add_edge(f"asset:{t.asset_id}", f"tech:{t.id}")
        for au in ctx.store.auth_surfaces():
            g.add_node(f"auth:{au.id}", kind="auth", label=au.kind, weight=12)
            g.add_edge(f"asset:{au.asset_id}", f"auth:{au.id}")

        # Top findings by risk (cap for readability).
        findings = sorted(
            [f for f in ctx.store.findings() if f.status == "validated"],
            key=lambda f: risk_by_finding.get(f.id, f.severity.rank * 10),
            reverse=True)[:40]
        fids = set()
        for f in findings:
            fids.add(f.id)
            g.add_node(f"finding:{f.id}", kind="finding", label=f.title[:40],
                       severity=f.severity.value,
                       weight=10 + f.severity.rank * 3)
            if g.has_node(f"asset:{f.asset_id}"):
                g.add_edge(f"asset:{f.asset_id}", f"finding:{f.id}")
        # Techniques for those findings.
        for m in ctx.store.mitre_mappings():
            if m.finding_id in fids:
                tn = f"tech_t:{m.technique_id}"
                g.add_node(tn, kind="technique",
                           label=f"{m.technique_id}", weight=14)
                g.add_edge(f"finding:{m.finding_id}", tn)

        json_data = {
            "nodes": [{"id": n, **g.nodes[n]} for n in g.nodes],
            "edges": [{"src": u, "dst": v} for u, v in g.edges],
            "views": ["graph", "relationship", "risk", "executive"],
        }
        (ctx.artifacts_dir / "attack_surface_full.json").write_text(
            json.dumps(json_data, default=str), encoding="utf-8")

        svg = self._render_svg(g) if g.number_of_nodes() else ""
        from pathlib import Path
        report_dir = Path(__file__).resolve().parent.parent / "reports" / ctx.scan_id
        report_dir.mkdir(parents=True, exist_ok=True)
        (report_dir / "attack_surface.svg").write_text(svg, encoding="utf-8")
        (report_dir / "graph.html").write_text(
            self._wrap_html(svg, ctx.scan_id), encoding="utf-8")

        ctx.store._visual = {  # type: ignore[attr-defined]
            "nodes": g.number_of_nodes(), "edges": g.number_of_edges(),
            "svg": "attack_surface.svg", "graph_html": "graph.html"}
        ctx.logger.info("Visual attack surface: %d nodes, %d edges -> graph.html",
                        g.number_of_nodes(), g.number_of_edges())

    def _render_svg(self, g) -> str:
        W, H, pad = 1280, 860, 60
        pos = nx.spring_layout(g, seed=42, k=1.4 / max(g.number_of_nodes(), 1) ** 0.5)
        xs = [p[0] for p in pos.values()]
        ys = [p[1] for p in pos.values()]
        minx, maxx = min(xs), max(xs)
        miny, maxy = min(ys), max(ys)

        def sx(x):
            return pad + (x - minx) / (maxx - minx or 1) * (W - 2 * pad)

        def sy(y):
            return pad + (y - miny) / (maxy - miny or 1) * (H - 2 * pad)

        parts = [f"<svg xmlns='http://www.w3.org/2000/svg' width='{W}' height='{H}' "
                 f"viewBox='0 0 {W} {H}' style='background:#0d1117'>"]
        for u, v in g.edges:
            parts.append(
                f"<line x1='{sx(pos[u][0]):.1f}' y1='{sy(pos[u][1]):.1f}' "
                f"x2='{sx(pos[v][0]):.1f}' y2='{sy(pos[v][1]):.1f}' "
                f"stroke='#30363d' stroke-width='0.7'/>")
        for n in g.nodes:
            d = g.nodes[n]
            kind = d.get("kind", "asset")
            color = (_SEV_COLOR.get(d.get("severity", ""), "#888")
                     if kind == "finding" else _KIND_COLOR.get(kind, "#888"))
            r = 4 + min(14, d.get("weight", 10) / 4)
            x, y = sx(pos[n][0]), sy(pos[n][1])
            parts.append(f"<circle cx='{x:.1f}' cy='{y:.1f}' r='{r:.1f}' "
                         f"fill='{color}' fill-opacity='0.85' stroke='#0d1117'/>")
            if r >= 9:  # label only prominent nodes
                lbl = html.escape(str(d.get("label", ""))[:24])
                parts.append(f"<text x='{x + r + 2:.1f}' y='{y + 3:.1f}' "
                             f"fill='#c9d1d9' font-size='9' "
                             f"font-family='Segoe UI,Arial'>{lbl}</text>")
        parts.append("</svg>")
        return "".join(parts)

    def _wrap_html(self, svg: str, scan_id: str) -> str:
        legend = "".join(
            f"<span style='color:{c}'>&#9679; {k}</span> "
            for k, c in {**_KIND_COLOR, "critical/high finding": "#b30000"}.items())
        return (f"<!doctype html><html><head><meta charset='utf-8'>"
                f"<title>VulnaX-Pro Attack Surface — {scan_id}</title></head>"
                f"<body style='background:#0d1117;color:#c9d1d9;"
                f"font-family:Segoe UI,Arial;margin:0;padding:16px'>"
                f"<h2>Attack Surface Map — {scan_id}</h2>"
                f"<div style='margin:8px 0'>{legend}</div>{svg}</body></html>")
