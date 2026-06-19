"""ReportingEngine (Stage 8): render HTML / Markdown / JSON reports."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from core.models import InterfaceAsset, Severity

from .base import Engine

ROOT = Path(__file__).resolve().parent.parent

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_COLOR = {"critical": "#b30000", "high": "#e34a33", "medium": "#fc8d59",
              "low": "#2c7fb8", "info": "#888"}


class ReportingEngine(Engine):
    name = "reporting"
    stage = 18
    depends_on = ("ai_analyst",)

    async def run(self, ctx) -> None:
        report_dir = ROOT / "reports" / ctx.scan_id
        output_dir = ROOT / "output" / ctx.scan_id
        report_dir.mkdir(parents=True, exist_ok=True)
        output_dir.mkdir(parents=True, exist_ok=True)

        model = self._assemble(ctx)
        formats = ctx.config.get("report.formats", ["html", "md", "json"])

        if "json" in formats:
            (output_dir / "result.json").write_text(
                json.dumps(model, indent=2, default=str), encoding="utf-8")
        if "md" in formats:
            (report_dir / "technical.md").write_text(
                self._render_md(model), encoding="utf-8")
        if "html" in formats:
            (report_dir / "report.html").write_text(
                self._render_html(model), encoding="utf-8")

        # Persist embedded store (SQLite).
        try:
            ctx.store.persist_sqlite(output_dir / "scan.db")
        except Exception as exc:  # noqa: BLE001
            ctx.logger.debug("sqlite persist failed: %s", exc)

        ctx.store._report_paths = {  # type: ignore[attr-defined]
            "html": str(report_dir / "report.html"),
            "md": str(report_dir / "technical.md"),
            "json": str(output_dir / "result.json"),
        }
        ctx.logger.info("Reports written to %s", report_dir)

    # ---- assemble --------------------------------------------------------
    def _assemble(self, ctx) -> dict:
        risk_by_finding = {r.subject_id: r for r in ctx.store.risks()
                           if r.subject_type == "finding"}
        self._mbf: dict[str, list] = {}
        for m in ctx.store.mitre_mappings():
            self._mbf.setdefault(m.finding_id, []).append(
                f"{m.technique_id} {m.technique_name}")
        findings = [f for f in ctx.store.findings() if f.status == "validated"]
        findings.sort(key=lambda f: (
            -risk_by_finding.get(f.id).score if risk_by_finding.get(f.id) else 0,
            _SEV_ORDER.get(f.severity.value, 9)))

        sev_counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in findings:
            sev_counts[f.severity.value] += 1

        bundle = ctx.store.bundle()
        params = ctx.store.parameters()
        param_cats: dict[str, int] = {}
        for p in params:
            param_cats[p.category] = param_cats.get(p.category, 0) + 1
        groups = sorted(ctx.store.finding_groups(),
                        key=lambda g: -g.risk_score)
        summary = {
            "assets_found": len(bundle["assets"]),
            "live_assets": len(ctx.store.assets(status="live")),
            "services": len(bundle["services"]),
            "technologies": len(bundle["technologies"]),
            "urls": len(bundle["endpoints"]),
            "js_files": len(bundle["js_assets"]),
            "api_endpoints": len(bundle["api_endpoints"]),
            "parameters": len(params),
            "finding_groups": len(groups),
            "findings_by_severity": sev_counts,
            "critical_paths": sum(
                1 for p in ctx.store.attack_paths()
                if p.impact.rank >= Severity.HIGH.rank),
            "mitre_techniques": len(getattr(ctx.store, "_mitre", {}).get(
                "techniques", [])),
            "mitre_tactics": len(getattr(ctx.store, "_mitre", {}).get("tactics", [])),
            "mitre_coverage": getattr(ctx.store, "_mitre", {}).get("coverage", 0),
            "posture_score": getattr(ctx.store, "_posture", {}).get("overall_score", 0),
            "posture_grade": getattr(ctx.store, "_posture", {}).get("grade", "-"),
            "interfaces": ctx.store.count(InterfaceAsset) if hasattr(
                ctx.store, "count") else 0,
            "exposure_changes": sum(getattr(ctx.store, "_exposure", {}).get(
                "summary", {}).get("counts", {}).values()),
        }

        return {
            "scan": {
                "id": ctx.scan_id,
                "profile": ctx.config.get("profile"),
                "scope": ctx.scope.roots,
                "started_at": ctx.started_at.isoformat(),
                "finished_at": datetime.now(timezone.utc).isoformat(),
            },
            "summary": summary,
            "ai_summary": getattr(ctx.store, "_ai_summary", ""),
            "findings": [self._finding_view(f, risk_by_finding.get(f.id))
                         for f in findings],
            "finding_groups": [g.model_dump(mode="json") for g in groups],
            "parameters_summary": {
                "total": len(params), "by_category": param_cats,
                "top_risky": [
                    {"name": p.name, "category": p.category, "risk": p.risk,
                     "sources": p.sources, "locations": p.locations[:3]}
                    for p in sorted(params, key=lambda p: (
                        {"high": 0, "medium": 1, "low": 2, "info": 3}[p.risk],
                        -p.confidence))[:25]],
            },
            "attack_paths": [p.model_dump(mode="json")
                             for p in sorted(ctx.store.attack_paths(),
                                             key=lambda p: -p.risk_score)],
            "mitre": self._mitre_view(ctx),
            "posture": getattr(ctx.store, "_posture", {}),
            "exposure": getattr(ctx.store, "_exposure", {}),
            "adversary": getattr(ctx.store, "_adversary", {}),
            "api_graph": getattr(ctx.store, "_api_graph", {}),
            "visual": getattr(ctx.store, "_visual", {}),
            "ai_research": getattr(ctx.store, "_ai_research", {}),
            "criticality": [c.model_dump(mode="json") for c in sorted(
                ctx.store.asset_criticality(),
                key=lambda c: -c.attack_priority)[:15]],
            "interfaces": [i.model_dump(mode="json")
                           for i in ctx.store.interface_assets()],
            "assets": [a.model_dump(mode="json")
                       for a in ctx.store.assets(status="live")],
            "technologies": [t.model_dump(mode="json")
                             for t in ctx.store.technologies()],
            "metrics": ctx.metrics.as_dict(),
            "raw": bundle,
        }

    def _finding_view(self, f, risk) -> dict:
        d = f.model_dump(mode="json")
        d["risk_score"] = risk.score if risk else 0
        d["mitre"] = self._mbf.get(f.id, [])
        return d

    def _mitre_view(self, ctx) -> dict:
        mitre = getattr(ctx.store, "_mitre", {}) or {}
        mappings = ctx.store.mitre_mappings()
        # technique clusters: technique -> count + name + tactic
        clusters: dict[str, dict] = {}
        for m in mappings:
            c = clusters.setdefault(m.technique_id, {
                "technique_id": m.technique_id, "technique_name": m.technique_name,
                "tactic": m.tactic_name, "count": 0})
            c["count"] += 1
        scenarios = sorted(ctx.store.threat_scenarios(),
                           key=lambda s: -s.risk_score)
        return {
            "enabled": bool(mappings),
            "kb_version": mitre.get("kb_version", ""),
            "coverage": mitre.get("coverage", 0),
            "techniques": mitre.get("techniques", []),
            "tactics": mitre.get("tactics", []),
            "heatmap": mitre.get("heatmap", []),
            "mitigations": mitre.get("mitigations", []),
            "risk": mitre.get("risk", {}),
            "clusters": sorted(clusters.values(), key=lambda x: -x["count"]),
            "scenarios": [s.model_dump(mode="json") for s in scenarios],
        }

    # ---- markdown --------------------------------------------------------
    def _render_md(self, m: dict) -> str:
        s = m["summary"]
        lines = [
            f"# VulnaX-Pro Report — {m['scan']['id']}",
            "",
            f"**Profile:** {m['scan']['profile']}  |  **Scope:** "
            f"{', '.join(m['scan']['scope'])}",
            "",
            "## Executive Summary", "", m.get("ai_summary", ""), "",
        ]
        lines += self._exec_md(m)
        lines += [
            "## Posture", "",
            f"- Live assets: {s['live_assets']} / {s['assets_found']}",
            f"- Services: {s['services']}  |  Technologies: {s['technologies']}",
            f"- URLs: {s['urls']}  |  JS files: {s['js_files']}  |  "
            f"API endpoints: {s['api_endpoints']}",
            f"- Findings: " + ", ".join(
                f"{k} {v}" for k, v in s["findings_by_severity"].items() if v),
            f"- Parameters catalogued: {s.get('parameters', 0)}  |  "
            f"Correlation groups: {s.get('finding_groups', 0)}",
            f"- Critical attack paths: {s['critical_paths']}",
            "",
        ]
        if m.get("finding_groups"):
            lines += ["## Correlation Groups", ""]
            for g in m["finding_groups"]:
                lines += [
                    f"- **[{g['kind']}] {g['title']}** "
                    f"(sev {g['severity']}, risk {g['risk_score']}, "
                    f"{len(g['finding_ids'])} findings) - "
                    f"root cause: {g['root_cause'] or 'n/a'}",
                ]
            lines.append("")
        mi = m.get("mitre", {})
        if mi.get("enabled"):
            lines += ["## MITRE ATT&CK Intelligence", "",
                      f"Coverage: {mi['coverage']}% of tactics | "
                      f"{len(mi['techniques'])} techniques | "
                      f"{len(mi['tactics'])} tactics (KB {mi['kb_version']})",
                      "", "### Tactic Heatmap (finding density / risk)", ""]
            for c in mi.get("heatmap", []):
                if c["finding_density"]:
                    lines.append(
                        f"- {c['name']}: {c['technique_count']} techniques, "
                        f"{c['finding_density']} findings, risk {c['risk_density']}")
            if mi.get("scenarios"):
                lines += ["", "### Threat Scenarios (Adversary Journeys)", ""]
                for s in mi["scenarios"]:
                    lines += [f"**{s['title']}** (risk {s['risk_score']})",
                              s["narrative"], ""]
            if mi.get("clusters"):
                lines += ["### Technique Clusters", ""]
                for c in mi["clusters"][:15]:
                    lines.append(f"- {c['technique_id']} {c['technique_name']} "
                                 f"({c['tactic']}) - {c['count']} finding(s)")
            if mi.get("mitigations"):
                lines += ["", "### Mitigation Recommendations", ""]
                for mit in mi["mitigations"][:12]:
                    lines.append(f"- {mit['id']} {mit['name']} "
                                 f"(addresses {mit['technique_count']} technique(s))")
            lines.append("")
        lines += ["## Findings", ""]
        for f in m["findings"]:
            lines += [
                f"### [{f['severity'].upper()}] {f['title']}  "
                f"(risk {f['risk_score']})",
                f"- **Target:** {f['target']}",
                f"- **Confidence:** {f['confidence']['score']} "
                f"({f['confidence']['signals']} signals)",
                f"- **Impact:** {f['impact']}",
                f"- **Remediation:** {f['remediation']}",
            ]
            if f.get("cve_ids"):
                lines.append(f"- **CVEs:** {', '.join(f['cve_ids'])}")
            if f.get("mitre"):
                lines.append(f"- **ATT&CK:** {', '.join(f['mitre'])}")
            lines.append("- **Evidence:**")
            for e in f["evidence"]:
                lines.append(f"  - {e['summary']}")
            if f.get("ai"):
                lines.append(f"- **AI:** {f['ai'].get('explanation','')}")
            lines.append("")
        if m["attack_paths"]:
            lines += ["## Attack Paths", ""]
            for p in m["attack_paths"]:
                lines += [
                    f"### [{p['impact'].upper()}] {p['kind']} "
                    f"(risk {p['risk_score']}, likelihood {p['likelihood']})",
                    p["narrative"], "",
                ]
        ps = m.get("parameters_summary", {})
        if ps.get("total"):
            lines += ["## Parameter Inventory", "",
                      f"Total parameters: {ps['total']}",
                      "By category: " + ", ".join(
                          f"{k} {v}" for k, v in sorted(ps["by_category"].items())),
                      "", "Top risk parameters:", ""]
            for p in ps["top_risky"]:
                lines.append(f"- `{p['name']}` - {p['category']} ({p['risk']}) "
                             f"via {', '.join(p['sources'])}")
            lines.append("")
        lines += self._intel_md(m)
        return "\n".join(lines)

    def _exec_md(self, m: dict) -> list[str]:
        p = m.get("posture", {})
        s = m["summary"]
        adv = m.get("adversary", {})
        out = ["## Executive Intelligence", ""]
        if p:
            out += [f"- **Security Posture:** {p.get('overall_score', 0)}/100 "
                    f"(grade {p.get('grade', '-')})",
                    f"- **Risk Index:** {p.get('risk_index', 0)}  |  "
                    f"**Exposure Index:** {p.get('exposure_index', 0)}  |  "
                    f"**Maturity Index:** {p.get('maturity_index', 0)}"]
        out += [f"- **Attack Surface:** {s['live_assets']} live assets, "
                f"{s['urls']} URLs, {s['api_endpoints']} APIs, "
                f"{s.get('parameters', 0)} parameters",
                f"- **ATT&CK Coverage:** {s.get('mitre_coverage', 0)}%  |  "
                f"**Notable Interfaces:** {s.get('interfaces', 0)}"]
        exp = m.get("exposure", {}).get("summary", {})
        if exp.get("has_baseline"):
            out.append(f"- **Exposure Change vs last scan:** "
                       f"{s.get('exposure_changes', 0)} changes")
        if adv.get("attractive_assets"):
            tops = ", ".join(a["host"] for a in adv["attractive_assets"][:3])
            out.append(f"- **Most attractive assets:** {tops}")
        out.append("")
        return out

    def _intel_md(self, m: dict) -> list[str]:
        out: list[str] = []
        crit = m.get("criticality", [])
        if crit:
            out += ["## Asset Criticality (attacker priority)", ""]
            for c in crit[:10]:
                out.append(f"- `{c['host']}` - priority {c['attack_priority']} "
                           f"({c['band']}), exposure {c['exposure']}, "
                           f"business impact {c['business_impact']}")
            out.append("")
        adv = m.get("adversary", {})
        if adv:
            out += ["## Adversary Simulation", "",
                    f"**Likely objectives:** {', '.join(adv.get('objectives', [])) or 'n/a'}",
                    "", "**Likely entry points:**"]
            for e in adv.get("entry_points", [])[:6]:
                out.append(f"- {e['title']} on {e.get('host') or e['target']}"
                           + (f" ({e['technique']})" if e.get("technique") else ""))
            if adv.get("data_targets"):
                out += ["", "**Potential data targets:**"]
                for d in adv["data_targets"][:6]:
                    out.append(f"- {d['host']} via {d['via']}")
            if adv.get("top_narrative"):
                out += ["", f"**Narrative:** {adv['top_narrative']}", ""]
        exp = m.get("exposure", {}).get("summary", {})
        if exp.get("has_baseline"):
            c = exp.get("counts", {})
            out += ["## Exposure Change Report", "",
                    f"Compared to previous scan ({exp.get('previous_scan')}):",
                    f"- New assets: {c.get('new_assets',0)} | Removed: "
                    f"{c.get('removed_assets',0)}",
                    f"- New endpoints: {c.get('new_endpoints',0)} | New params: "
                    f"{c.get('new_parameters',0)} | New services: "
                    f"{c.get('new_services',0)}",
                    f"- New technologies: {c.get('tech_added',0)} | New findings: "
                    f"{c.get('new_findings',0)}", ""]
        elif m.get("exposure"):
            out += ["## Exposure Change Report", "",
                    "Baseline established (first assessment for this project). "
                    "Future scans will show what changed.", ""]
        ifaces = m.get("interfaces", [])
        if ifaces:
            out += ["## Notable Interfaces", ""]
            for i in ifaces[:15]:
                out.append(f"- [{i['interface_type']}] {i['url']} "
                           f"(conf {i['confidence']})")
            out.append("")
        res = m.get("ai_research", {})
        if res.get("investigation_paths"):
            out += ["## Recommended Investigation Paths", ""]
            for r in res["investigation_paths"][:8]:
                out.append(f"- {r}")
            out.append("")
        if m.get("visual", {}).get("graph_html"):
            out += [f"## Visual Attack Surface", "",
                    f"Interactive map: `reports/{m['scan']['id']}/"
                    f"{m['visual']['graph_html']}`", ""]
        return out

    def _intel_html(self, m: dict) -> str:
        p = m.get("posture", {})
        adv = m.get("adversary", {})
        crit = m.get("criticality", [])
        exp = m.get("exposure", {}).get("summary", {})
        ifaces = m.get("interfaces", [])
        res = m.get("ai_research", {})
        out = ["<h2>Executive Intelligence</h2>"]

        if p:
            comps = "".join(
                f"<tr><td>{_esc(k.replace('_',' '))}</td><td>{v}</td></tr>"
                for k, v in p.get("components", {}).items())
            grade = p.get("grade", "-")
            gcolor = ("#2da44e" if grade in ("A", "B") else "#d29922"
                      if grade in ("C", "D") else "#b30000")
            out.append(
                f"<div class='exec'><b>Security Posture:</b> "
                f"<span style='color:{gcolor};font-weight:700'>"
                f"{p.get('overall_score',0)}/100 (grade {grade})</span> &middot; "
                f"Risk Index {p.get('risk_index',0)} &middot; "
                f"Exposure Index {p.get('exposure_index',0)} &middot; "
                f"Maturity Index {p.get('maturity_index',0)}"
                f"<table class='ptable' style='margin-top:8px'>"
                f"<tr><th>Component</th><th>Score</th></tr>{comps}</table></div>")

        if crit:
            rows = "".join(
                f"<tr><td>{_esc(c['host'])}</td><td>{c['attack_priority']}</td>"
                f"<td>{c['band']}</td><td>{c['exposure']}</td>"
                f"<td>{c['business_impact']}</td></tr>" for c in crit[:12])
            out.append(
                "<h3>Asset Criticality (attacker priority)</h3>"
                "<table class='ptable'><tr><th>Host</th><th>Attack Priority</th>"
                f"<th>Band</th><th>Exposure</th><th>Business Impact</th></tr>{rows}"
                "</table>")

        if adv:
            eps = "".join(
                f"<li>{_esc(e['title'])} on {_esc(e.get('host') or e['target'])}"
                + (f" <span class='ttag'>{_esc(e['technique'])}</span>"
                   if e.get('technique') else "") + "</li>"
                for e in adv.get("entry_points", [])[:6])
            dts = "".join(f"<li>{_esc(d['host'])} via {_esc(d['via'])}</li>"
                          for d in adv.get("data_targets", [])[:6])
            out.append(
                "<h3>Adversary Simulation</h3>"
                f"<p><b>Likely objectives:</b> "
                f"{_esc(', '.join(adv.get('objectives', [])) or 'n/a')}</p>"
                f"<p><b>Likely entry points:</b></p><ul>{eps or '<li>none</li>'}</ul>"
                + (f"<p><b>Data targets:</b></p><ul>{dts}</ul>" if dts else "")
                + f"<p class='ai'><b>Narrative:</b> "
                f"{_esc(adv.get('top_narrative',''))}</p>")

        if m.get("exposure"):
            if exp.get("has_baseline"):
                c = exp.get("counts", {})
                out.append(
                    "<h3>Exposure Change Report</h3>"
                    f"<p class='sub'>vs previous scan {exp.get('previous_scan')}</p>"
                    f"<p>New assets {c.get('new_assets',0)} · removed "
                    f"{c.get('removed_assets',0)} · new endpoints "
                    f"{c.get('new_endpoints',0)} · new params "
                    f"{c.get('new_parameters',0)} · new services "
                    f"{c.get('new_services',0)} · new findings "
                    f"{c.get('new_findings',0)}</p>")
            else:
                out.append("<h3>Exposure Change Report</h3><p class='sub'>Baseline "
                           "established (first assessment). Future scans show diffs."
                           "</p>")

        if ifaces:
            rows = "".join(
                f"<tr><td>{_esc(i['interface_type'])}</td>"
                f"<td>{_esc(i['url'])}</td><td>{i['confidence']}</td></tr>"
                for i in ifaces[:15])
            out.append("<h3>Notable Interfaces</h3><table class='ptable'>"
                       "<tr><th>Type</th><th>URL</th><th>Conf</th></tr>"
                       f"{rows}</table>")

        if res.get("investigation_paths"):
            items = "".join(f"<li>{_esc(x)}</li>"
                            for x in res["investigation_paths"][:8])
            out.append(f"<h3>Recommended Investigation Paths</h3><ul>{items}</ul>")

        if m.get("visual", {}).get("graph_html"):
            out.append(f"<h3>Visual Attack Surface</h3><p>Interactive map: "
                       f"<a href='{m['visual']['graph_html']}' "
                       f"style='color:#58a6ff'>{m['visual']['graph_html']}</a> "
                       f"({m['visual'].get('nodes',0)} nodes)</p>")
        return "".join(out)

    # ---- html ------------------------------------------------------------
    def _render_html(self, m: dict) -> str:
        s = m["summary"]
        cards = "".join(
            f"<div class='card'><div class='n'>{v:,}</div><div class='l'>{k}</div></div>"
            for k, v in [
                ("Assets", s["assets_found"]), ("Live", s["live_assets"]),
                ("Services", s["services"]), ("Tech", s["technologies"]),
                ("URLs", s["urls"]), ("JS", s["js_files"]),
                ("APIs", s["api_endpoints"]), ("Params", s.get("parameters", 0)),
                ("Groups", s.get("finding_groups", 0)),
                ("Crit Paths", s["critical_paths"]),
                ("ATT&CK Tech", s.get("mitre_techniques", 0)),
                ("Coverage%", s.get("mitre_coverage", 0)),
                ("Posture", s.get("posture_score", 0)),
                ("Interfaces", s.get("interfaces", 0)),
            ])
        sev_bar = "".join(
            f"<span class='sev' style='background:{_SEV_COLOR[k]}'>{k}: {v}</span>"
            for k, v in s["findings_by_severity"].items() if v)

        findings_html = ""
        for f in m["findings"]:
            color = _SEV_COLOR.get(f["severity"], "#888")
            ev = "".join(f"<li>{_esc(e['summary'])}</li>" for e in f["evidence"])
            cves = (f"<p><b>CVEs:</b> {', '.join(f['cve_ids'])}</p>"
                    if f.get("cve_ids") else "")
            attck = ("".join(f"<span class='ttag'>{_esc(t)}</span>"
                             for t in f.get("mitre", []))
                     if f.get("mitre") else "")
            ai = (f"<p class='ai'><b>AI:</b> {_esc(f['ai'].get('explanation',''))}</p>"
                  if f.get("ai") else "")
            findings_html += f"""
            <details class='finding'>
              <summary><span class='badge' style='background:{color}'>
              {f['severity'].upper()}</span> {_esc(f['title'])}
              <span class='risk'>risk {f['risk_score']}</span></summary>
              <p><b>Target:</b> {_esc(f['target'])}</p>
              <p><b>Confidence:</b> {f['confidence']['score']}
                 ({f['confidence']['signals']} signals)</p>
              <p><b>Impact:</b> {_esc(f['impact'])}</p>
              <p><b>Remediation:</b> {_esc(f['remediation'])}</p>
              {cves}
              {f"<p><b>ATT&CK:</b> {attck}</p>" if attck else ""}
              <p><b>Evidence:</b></p><ul>{ev}</ul>
              {ai}
            </details>"""

        groups_html = ""
        for g in m.get("finding_groups", []):
            color = _SEV_COLOR.get(g["severity"], "#888")
            groups_html += f"""
            <div class='path'>
              <h3><span class='badge' style='background:{color}'>
              {g['kind'].upper()}</span> {_esc(g['title'])}
              <span class='risk'>risk {g['risk_score']}</span></h3>
              <p><b>Root cause:</b> {_esc(g['root_cause'] or 'n/a')} &middot;
                 {len(g['finding_ids'])} findings</p>
              <p class='sub'>{_esc(g['summary'])}</p>
            </div>"""

        ps = m.get("parameters_summary", {})
        params_html = ""
        if ps.get("total"):
            cat = ", ".join(f"{k}: {v}" for k, v in sorted(
                ps["by_category"].items()))
            rows = "".join(
                f"<tr><td><code>{_esc(p['name'])}</code></td><td>{p['category']}</td>"
                f"<td>{p['risk']}</td><td>{', '.join(p['sources'])}</td></tr>"
                for p in ps["top_risky"])
            params_html = f"""
            <p class='sub'>Total {ps['total']} parameters - {_esc(cat)}</p>
            <table class='ptable'><tr><th>Name</th><th>Category</th>
            <th>Risk</th><th>Sources</th></tr>{rows}</table>"""

        mi = m.get("mitre", {})
        mitre_html = "<p>ATT&CK mapping not available.</p>"
        if mi.get("enabled"):
            cells = ""
            for c in mi.get("heatmap", []):
                rd = c["risk_density"]
                bg = ("#b30000" if rd >= 65 else "#e34a33" if rd >= 40 else
                      "#fc8d59" if rd > 0 else "#161b22")
                fg = "#fff" if rd > 0 else "#566"
                cells += (f"<div class='hcell' style='background:{bg};color:{fg}'>"
                          f"<div class='ht'>{_esc(c['name'])}</div>"
                          f"<div class='hn'>{c['finding_density']}</div>"
                          f"<div class='hs'>{c['technique_count']} tech</div></div>")
            scen = ""
            for s in mi.get("scenarios", []):
                techs = " &rarr; ".join(_esc(t) for t in s["technique_ids"])
                scen += (f"<div class='path'><h3>{_esc(s['title'])}"
                         f"<span class='risk'>risk {s['risk_score']}</span></h3>"
                         f"<p>{_esc(s['narrative'])}</p>"
                         f"<p class='sub'>Chain: {techs}</p></div>")
            clusters = "".join(
                f"<tr><td>{_esc(c['technique_id'])}</td>"
                f"<td>{_esc(c['technique_name'])}</td><td>{_esc(c['tactic'])}</td>"
                f"<td>{c['count']}</td></tr>" for c in mi.get("clusters", [])[:20])
            mits = "".join(
                f"<tr><td>{_esc(x['id'])}</td><td>{_esc(x['name'])}</td>"
                f"<td>{x['technique_count']}</td></tr>"
                for x in mi.get("mitigations", [])[:15])
            mitre_html = f"""
            <p class='sub'>Coverage {mi['coverage']}% of tactics ·
            {len(mi['techniques'])} techniques · {len(mi['tactics'])} tactics ·
            KB {_esc(mi['kb_version'])}</p>
            <h3>Tactic Heatmap</h3><div class='heat'>{cells}</div>
            <h3>Threat Scenarios (Adversary Journeys)</h3>
            {scen or '<p>No multi-tactic scenarios.</p>'}
            <h3>Technique Clusters</h3>
            <table class='ptable'><tr><th>Technique</th><th>Name</th><th>Tactic</th>
            <th>Findings</th></tr>{clusters}</table>
            <h3>Mitigation Recommendations</h3>
            <table class='ptable'><tr><th>ID</th><th>Mitigation</th>
            <th>Techniques</th></tr>{mits}</table>"""

        intel_html = self._intel_html(m)

        paths_html = ""
        for p in m["attack_paths"]:
            color = _SEV_COLOR.get(p["impact"], "#888")
            steps = "".join(f"<li>{_esc(st['action'])}</li>" for st in p["steps"])
            paths_html += f"""
            <div class='path'>
              <h3><span class='badge' style='background:{color}'>
              {p['impact'].upper()}</span> {p['kind']}
              <span class='risk'>risk {p['risk_score']}</span></h3>
              <p>{_esc(p['narrative'])}</p><ol>{steps}</ol>
            </div>"""

        return f"""<!doctype html><html><head><meta charset='utf-8'>
<title>VulnaX-Pro — {m['scan']['id']}</title><style>
body{{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#0f1419;color:#e6e6e6}}
header{{background:#11171f;padding:24px 32px;border-bottom:2px solid #1f6feb}}
header h1{{margin:0;color:#58a6ff}} .sub{{color:#8b949e}}
main{{padding:24px 32px;max-width:1100px;margin:auto}}
.cards{{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:8px;
padding:14px 20px;min-width:96px;text-align:center}}
.card .n{{font-size:26px;font-weight:700;color:#58a6ff}}
.card .l{{font-size:12px;color:#8b949e;text-transform:uppercase}}
.sev{{display:inline-block;color:#fff;padding:3px 10px;border-radius:12px;
margin:2px;font-size:12px}}
.badge{{color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700}}
.risk{{float:right;color:#8b949e;font-size:12px}}
.finding,.path{{background:#161b22;border:1px solid #30363d;border-radius:8px;
padding:12px 16px;margin:10px 0}}
summary{{cursor:pointer;font-weight:600}} .ai{{color:#a5d6ff}}
h2{{border-bottom:1px solid #30363d;padding-bottom:6px;color:#c9d1d9}}
.ptable{{width:100%;border-collapse:collapse;font-size:13px}}
.ptable th,.ptable td{{border:1px solid #30363d;padding:5px 8px;text-align:left}}
.ptable th{{background:#161b22;color:#8b949e}}
.heat{{display:flex;flex-wrap:wrap;gap:4px;margin:8px 0}}
.hcell{{flex:1 1 90px;min-width:90px;border-radius:6px;padding:8px 6px;
text-align:center;border:1px solid #30363d}}
.hcell .ht{{font-size:10px;text-transform:uppercase;opacity:.85}}
.hcell .hn{{font-size:22px;font-weight:700}} .hcell .hs{{font-size:10px;opacity:.8}}
.ttag{{display:inline-block;background:#1f6feb33;color:#79c0ff;border:1px solid
#1f6feb;border-radius:4px;padding:1px 6px;margin:2px;font-size:11px}}
.exec{{background:#161b22;border-left:3px solid #1f6feb;padding:12px 16px}}
code{{color:#ffa657}}</style></head><body>
<header><h1>VulnaX-Pro</h1>
<div class='sub'>Scan {m['scan']['id']} · profile {m['scan']['profile']} ·
scope {', '.join(m['scan']['scope'])}</div></header>
<main>
<div class='cards'>{cards}</div>
<div>{sev_bar}</div>
<h2>Executive Summary</h2>
<div class='exec'>{_esc(m.get('ai_summary',''))}</div>
{intel_html}
<h2>MITRE ATT&CK Intelligence</h2>{mitre_html}
<h2>Correlation Groups</h2>{groups_html or '<p>No correlation groups.</p>'}
<h2>Attack Paths</h2>{paths_html or '<p>No attack paths reconstructed.</p>'}
<h2>Findings ({len(m['findings'])})</h2>{findings_html or '<p>No findings.</p>'}
<h2>Parameter Inventory</h2>{params_html or '<p>No parameters catalogued.</p>'}
<h2>Methodology</h2><p class='sub'>Generated by VulnaX-Pro. Authorized assessment
only. Tool versions and full logs in artifacts/{m['scan']['id']}/run.log.</p>
</main></body></html>"""


def _esc(s) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))
