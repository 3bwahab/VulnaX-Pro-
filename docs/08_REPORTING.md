# 08 — Reporting Architecture

## 1. Goals

Commercial-grade reports in multiple formats and audiences, all rendered from the
single consolidated result bundle. Every finding carries evidence, confidence,
risk, impact, remediation, and references.

## 2. Formats × Audiences

| Report | Format(s) | Audience | Content |
|--------|-----------|----------|---------|
| Executive | HTML, MD | Leadership | Risk posture, top risks, attack paths, trends |
| Technical | HTML, MD | Engineers/Pentesters | Full findings w/ evidence & remediation |
| Asset Inventory | HTML, MD, CSV | Ops/Asset owners | Assets, services, tech, exposure |
| Attack Surface | HTML | Security team | Graph visualization + exposure maps |
| Attack Path | HTML, MD | Security team | Narratives + step chains |
| Machine | JSON | Tooling/SIEM | Full schema bundle |

## 3. Pipeline (`engines/reporting/`)

```
assemble.py     load result bundle from store → build ReportModel (view models)
  ↓
render_html.py  Jinja2 → templates/report/*.html.j2  (self-contained, inline CSS/JS)
render_md.py    Jinja2 → markdown
render_json.py  schema-validated JSON bundle
  ↓
evidence_embed.py  inline snippets, link artifacts (screenshots, raw)
  ↓
write to reports/<scan_id>/{executive,technical,...}.{html,md} + result.json
```

## 4. ReportModel (view layer)

A presentation-oriented projection of core models (not the storage models):
- `RiskPostureView` — counts by band, score gauge, trend vs previous scan.
- `FindingView` — finding + resolved evidence snippets + AI annotation + risk.
- `AssetView` — asset + services + tech + endpoints rollup + exposure score.
- `PathView` — attack path with rendered narrative + step diagram.
- `SurfaceView` — graph nodes/edges for embedded visualization.

## 5. HTML Report Design

- Single self-contained `.html` (inline CSS/JS, no external CDN) → portable.
- Sections: cover → executive summary → risk dashboard → attack paths → findings
  (sortable/filterable table) → asset inventory → surface graph → appendix
  (methodology, tool versions, scope).
- Severity-colored, collapsible findings with embedded evidence + copy buttons.
- Surface graph rendered client-side (vis-network / d3 from embedded JSON).
- Print-friendly stylesheet for PDF export via browser.

## 6. Finding Presentation (mandatory fields)

Each rendered finding shows:
```
Title · Severity badge · Risk score · Confidence (with rationale)
Affected asset / target
Evidence (one block per Evidence item: summary + structured data + artifact link)
Impact
Remediation (actionable)
References (CVE/CWE/vendor/links)
Provenance (detected_by engines/tools)
AI explanation (if available, clearly labeled as AI-generated, advisory)
```

## 7. Determinism & Diffing

- Reports are deterministic given the same bundle (stable ordering by risk then id).
- `--compare <prev_scan_id>` annotates findings as **New / Recurring / Resolved**
  using stable content-hash ids → regression tracking over time.

## 8. Templating

- Jinja2 templates in `templates/report/`, partials in `partials/`.
- Theme/branding via `theme.json` (logo, colors) → white-label ready.
- New report = new template auto-discovered + registered renderer; no engine change.

## 9. Performance

- Streaming/paginated rendering for large asset/endpoint tables.
- Heavy assets (graph data) embedded as compressed JSON.
- Rendering runs after synthesis; never blocks discovery.
