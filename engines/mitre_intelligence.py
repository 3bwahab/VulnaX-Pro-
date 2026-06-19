"""MitreIntelligenceEngine (Stage 14): adversary-centric ATT&CK intelligence.

Translates findings into ATT&CK techniques/tactics, correlates them into technique/
tactic clusters and threat scenarios (adversary journeys), builds an ATT&CK
relationship graph, computes a tactic heatmap + coverage score, derives an ATT&CK
risk overlay, and aggregates mitigation intelligence. Additive: existing Risk /
Attack Path / Graph engines are not modified — this layer overlays on their output.
"""
from __future__ import annotations

import json

import networkx as nx

from core.models import MitreMapping, Relationship, ThreatScenario
from mitre import map_finding
from mitre.knowledge_base import load_kb

from .base import Engine

# Tactic weights for ATT&CK risk overlay (higher = closer to attacker objectives).
_TACTIC_WEIGHT = {
    "TA0043": 3, "TA0042": 3, "TA0001": 12, "TA0002": 10, "TA0003": 9,
    "TA0004": 12, "TA0005": 6, "TA0006": 12, "TA0007": 5, "TA0008": 9,
    "TA0009": 8, "TA0011": 7, "TA0010": 10, "TA0040": 12,
}


class MitreIntelligenceEngine(Engine):
    name = "mitre_intelligence"
    stage = 14
    depends_on = ("vulnerability_correlation", "finding_correlation",
                  "risk_scoring", "attack_path", "attack_surface_graph")

    async def run(self, ctx) -> None:
        kb = load_kb()
        findings = [f for f in ctx.store.findings() if f.status == "validated"]
        risk_by_finding = {r.subject_id: r.score for r in ctx.store.risks()
                           if r.subject_type == "finding"}

        # 1) Map findings -> ATT&CK techniques/tactics.
        mappings: list[MitreMapping] = []
        for f in findings:
            for tid, base_conf, reason in map_finding(f):
                tech = kb.technique(tid)
                if not tech:
                    continue
                tactic_id = kb.primary_tactic(tid)
                conf = round(min(0.97, base_conf * 0.6 + f.confidence.score * 0.4), 2)
                m = MitreMapping(
                    finding_id=f.id, asset_id=f.asset_id, technique_id=tid,
                    technique_name=tech["name"],
                    sub_technique_id=tid if "." in tid else None,
                    tactic_id=tactic_id, tactic_name=kb.tactic_name(tactic_id),
                    confidence=conf,
                    reasoning=f"{reason} (finding: {f.title})",
                    mitigations=[f"{x['id']} {x['name']}"
                                 for x in kb.mitigations_for(tid)])
                ctx.store.add(m)
                mappings.append(m)

        # 2) ATT&CK relationship graph + Relationship records.
        graph = self._build_graph(ctx, kb, mappings)

        # 3) Heatmap + coverage.
        heatmap = self._heatmap(kb, mappings, risk_by_finding, findings)
        covered = {m.tactic_id for m in mappings if m.tactic_id}
        coverage = round(100 * len(covered) / max(len(kb.tactics), 1))

        # 4) ATT&CK risk overlay per finding.
        mitre_risk = self._risk_overlay(ctx, kb, mappings, risk_by_finding)

        # 5) Threat scenarios (adversary journeys) per asset.
        scenarios = self._scenarios(ctx, kb, mappings, mitre_risk)

        # 6) Mitigation intelligence (aggregate, ranked by technique frequency).
        mitigations = self._mitigations(kb, mappings)

        techniques = sorted({m.technique_id for m in mappings})
        tactics = sorted(covered, key=kb.tactic_order)
        ctx.store._mitre = {  # type: ignore[attr-defined]
            "kb_version": kb.version,
            "techniques": techniques,
            "tactics": [kb.tactic_name(t) for t in tactics],
            "coverage": coverage,
            "heatmap": heatmap,
            "risk": mitre_risk,
            "mitigations": mitigations,
            "graph_nodes": graph.number_of_nodes(),
            "graph_edges": graph.number_of_edges(),
        }

        # CLI / dashboard counters.
        for k, v in {
            "mitre_techniques": len(techniques),
            "mitre_tactics": len(tactics),
            "adversary_paths": len(scenarios),
            "threat_scenarios": len({s.objective for s in scenarios}) or len(scenarios),
            "mitre_coverage": coverage,
        }.items():
            ctx.bus._counters[k] = v
            ctx.bus.emit("counter", counter=k, value=v)

        ctx.logger.info(
            "MITRE: %d mappings, %d techniques, %d tactics, %d scenarios, %d%% coverage",
            len(mappings), len(techniques), len(tactics), len(scenarios), coverage)

    # ---- graph -----------------------------------------------------------
    def _build_graph(self, ctx, kb, mappings) -> nx.MultiDiGraph:
        g = nx.MultiDiGraph()
        for m in mappings:
            fnode = f"finding:{m.finding_id}"
            tnode = f"tech:{m.technique_id}"
            tac = f"tactic:{m.tactic_id}"
            g.add_node(fnode, kind="finding")
            g.add_node(tnode, kind="technique", label=m.technique_name)
            g.add_node(tac, kind="tactic", label=m.tactic_name)
            g.add_edge(fnode, tnode, kind="maps_to")
            g.add_edge(tnode, tac, kind="enables")
            ctx.store.add(Relationship(src_id=m.finding_id, src_type="finding",
                                       dst_id=m.technique_id, dst_type="technique",
                                       kind="maps_to"))
            ctx.store.add(Relationship(src_id=m.technique_id, src_type="technique",
                                       dst_id=m.tactic_id, dst_type="tactic",
                                       kind="enables"))
            for mit in kb.mitigations_for(m.technique_id):
                mnode = f"mit:{mit['id']}"
                g.add_node(mnode, kind="mitigation", label=mit["name"])
                g.add_edge(tnode, mnode, kind="mitigated_by")
        out = ctx.artifacts_dir / "mitre_graph.json"
        out.write_text(json.dumps({
            "nodes": [{"id": n, **g.nodes[n]} for n in g.nodes],
            "edges": [{"src": u, "dst": v, **d} for u, v, d in g.edges(data=True)],
        }, default=str), encoding="utf-8")
        return g

    # ---- heatmap ---------------------------------------------------------
    def _heatmap(self, kb, mappings, risk_by_finding, findings) -> list[dict]:
        sev_rank = {f.id: f.severity.rank for f in findings}
        cells: dict[str, dict] = {}
        for t in kb.ordered_tactics():
            cells[t["id"]] = {"tactic_id": t["id"], "name": t["name"], "order": t["order"],
                              "techniques": set(), "findings": 0, "risk": 0.0,
                              "max_sev": 0}
        for m in mappings:
            c = cells.get(m.tactic_id)
            if not c:
                continue
            c["techniques"].add(m.technique_id)
            c["findings"] += 1
            c["risk"] = max(c["risk"], risk_by_finding.get(m.finding_id, 0))
            c["max_sev"] = max(c["max_sev"], sev_rank.get(m.finding_id, 0))
        out = []
        for c in sorted(cells.values(), key=lambda x: x["order"]):
            out.append({
                "tactic_id": c["tactic_id"], "name": c["name"],
                "technique_count": len(c["techniques"]),
                "finding_density": c["findings"], "risk_density": round(c["risk"], 1),
                "max_severity": c["max_sev"]})
        return out

    # ---- risk overlay ----------------------------------------------------
    def _risk_overlay(self, ctx, kb, mappings, risk_by_finding) -> dict:
        by_finding: dict[str, list] = {}
        for m in mappings:
            by_finding.setdefault(m.finding_id, []).append(m)
        path_findings = set()
        for p in ctx.store.attack_paths():
            for step in p.steps:
                if step.finding_id:
                    path_findings.add(step.finding_id)
        out: dict[str, dict] = {}
        for fid, ms in by_finding.items():
            base = risk_by_finding.get(fid, 0)
            tw = max(_TACTIC_WEIGHT.get(m.tactic_id, 3) for m in ms)
            crit = max((kb.technique(m.technique_id) or {}).get("criticality", 0.5)
                       for m in ms) * 15
            path_bonus = 8 if fid in path_findings else 0
            attack_risk = min(100, round(base * 0.6 + tw + crit + path_bonus, 1))
            business_risk = min(100, round(attack_risk * 0.85 + path_bonus, 1))
            out[fid] = {"attack_risk": attack_risk, "business_risk": business_risk,
                        "base": base, "tactic_weight": tw}
        return out

    # ---- scenarios -------------------------------------------------------
    def _scenarios(self, ctx, kb, mappings, mitre_risk) -> list[ThreatScenario]:
        by_asset: dict[str, list] = {}
        for m in mappings:
            by_asset.setdefault(m.asset_id, []).append(m)
        host_by_asset = {a.id: a.host for a in ctx.store.assets()}
        scenarios: list[ThreatScenario] = []
        for asset_id, ms in by_asset.items():
            tactics = sorted({m.tactic_id for m in ms}, key=kb.tactic_order)
            if len(tactics) < 2:
                continue
            host = host_by_asset.get(asset_id, asset_id)
            # one representative technique per tactic, in kill-chain order.
            chain = []
            tech_ids = []
            finding_ids = []
            for tac in tactics:
                tac_ms = [m for m in ms if m.tactic_id == tac]
                best = max(tac_ms, key=lambda m: m.confidence)
                chain.append(f"{kb.tactic_name(tac)} ({best.technique_id} "
                             f"{best.technique_name})")
                tech_ids.append(best.technique_id)
                finding_ids.append(best.finding_id)
            objective = kb.tactic_name(tactics[-1])
            risk = max((mitre_risk.get(fid, {}).get("attack_risk", 0)
                        for fid in finding_ids), default=0)
            narrative = (f"On {host}, an adversary could chain "
                         + " -> ".join(chain)
                         + f", culminating in {objective.lower()}.")
            s = ThreatScenario(
                title=f"Adversary journey on {host} ({objective})",
                asset_id=asset_id, tactic_chain=[kb.tactic_name(t) for t in tactics],
                technique_ids=tech_ids, finding_ids=finding_ids,
                narrative=narrative, objective=objective, risk_score=risk)
            ctx.store.add(s)
            scenarios.append(s)
        return scenarios

    # ---- mitigations -----------------------------------------------------
    def _mitigations(self, kb, mappings) -> list[dict]:
        freq: dict[str, dict] = {}
        for m in mappings:
            for mit in kb.mitigations_for(m.technique_id):
                slot = freq.setdefault(mit["id"], {"id": mit["id"], "name": mit["name"],
                                                   "techniques": set()})
                slot["techniques"].add(m.technique_id)
        out = [{"id": v["id"], "name": v["name"],
                "technique_count": len(v["techniques"])}
               for v in freq.values()]
        return sorted(out, key=lambda x: -x["technique_count"])
