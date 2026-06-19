# 15 — Attack Surface Intelligence Layer (Strategic Differentiation)

Moves VulnaX-Pro beyond "scanner" toward an **Attack Surface Management +
Threat-Intelligence + Security-Analytics** platform. The goal is not more
vulnerabilities — it is more *intelligence*: "what matters most / what changed /
what is most exposed / what would an attacker target first / what to investigate
next". Fully additive — **no existing engine was redesigned**; every new engine
composes existing store data.

---

## 1. New Engine Architecture

```
... attack_path(13) -> mitre_intelligence(14) ->
   asset_criticality(15) · exposure_intelligence(15) ·
   api_relationship(15) · interface_intelligence(15) ->
   security_posture(16) · adversary_simulation(16) · visual_attack_surface(16) ->
   ai_analyst(17, +research) -> reporting(18, +executive intelligence)
```

| Engine | Stage | Purpose |
|--------|-------|---------|
| AssetCriticalityEngine | 15 | importance / business-impact / exposure / attack-priority per asset |
| ExposureIntelligenceEngine | 15 | recon memory + diff vs previous scan (what changed/appeared/disappeared) |
| ApiRelationshipEngine | 15 | API/auth/trust/service graphs |
| InterfaceIntelligenceEngine | 15 | classify notable interfaces (Jenkins/Grafana/…); optional screenshots |
| SecurityPostureEngine | 16 | overall posture score + risk/exposure/maturity indices |
| AdversarySimulationEngine | 16 | objectives, entry points, attractive assets, escalation, data targets |
| VisualAttackSurfaceEngine | 16 | consolidated graph -> self-contained SVG + JSON (graph/risk/exec views) |

Risk-clustering is satisfied by the existing FindingCorrelationEngine (related /
root-cause / exposure / risk-cluster groups).

## 2. Data Models

`AssetCriticality` (importance, business_impact, exposure, attack_priority, band,
factors) · `ExposureDelta` (kind, subject, detail, severity) · `InterfaceAsset`
(url, interface_type, confidence, title, screenshot_path). Persisted to store +
result bundle + SQLite. Posture / adversary / visual / api-graph / ai-research are
ephemeral overlays on `ctx.store._*`, serialized into the report.

## 3. Internal Workflows

- **Recon memory** (`core/recon_memory.py`): per-project snapshots under
  `recon_memory/<project_id>/` (project = hash of scope roots) + `latest.json` +
  `trends.json`. Exposure engine loads latest, diffs, writes new snapshot + trend.
- **Criticality**: weighted factor model (auth, admin, sensitive keywords, tech
  risk, internet/cloud exposure, API sensitivity, graph centrality).
- **Posture**: 7 component metrics → overall score + grade + 3 indices, penalized
  by critical/high counts.
- **Adversary**: composes ATT&CK tactics (objectives), low-friction medium+ findings
  (entry points), top-criticality assets (attractive), attack paths (escalation),
  secret/cloud/git findings (data targets), threat scenarios (narratives).

## 4. Correlation Logic

API relationships: `service ─part_of─ api ─requires_auth─ auth`,
`auth ─token_for─ api`. Exposure correlation: set differences across assets /
endpoints / parameters / services / apis / technologies / findings → ExposureDelta
records + counts + trend series.

## 5. Risk-Scoring Enhancements

AssetCriticality adds an **attack-priority** dimension (importance×exposure×impact +
finding weight) — distinct from finding-level Risk and ATT&CK risk overlay. Posture
indices give portfolio-level risk/exposure/maturity. Existing RiskScoring untouched.

## 6. Visualization Architecture

`VisualAttackSurfaceEngine` builds a consolidated graph (assets, technologies, auth,
top findings, ATT&CK techniques), computes a deterministic `networkx` spring layout
in Python, and renders a **self-contained SVG** (no JS, no CDN) + `graph.html`
wrapper + `attack_surface_full.json` (drives graph/relationship/risk/executive
views). Node color by kind/severity, size by attack priority.

## 7. AI-Enhancement Architecture

AI Research Analyst (additive to AIAnalystEngine): produces structured intelligence —
interesting assets/endpoints/parameters/interfaces and recommended investigation
paths — stored in `ctx.store._ai_research`. The executive summary (LLM or offline)
already cites posture, ATT&CK coverage, and the top adversary journey.

## 8. Reporting Enhancements

New **Executive Intelligence** block + sections: Security Posture (score, grade,
component table, indices), Asset Criticality table, Adversary Simulation (objectives /
entry points / data targets / narrative), Exposure Change Report, Notable Interfaces,
Recommended Investigation Paths, and a link to the Visual Attack Surface map. New
cards: Posture, Interfaces, ATT&CK coverage.

## 9. Executive Intelligence Features

Non-technical stakeholders get: posture grade, top risks, critical assets, attack
surface size, exposure trend (vs last scan), ATT&CK coverage, attack-path summary,
and prioritized recommendations — all on the report's first screen.

## 10. Competitive Differentiation

| Capability | Why scanners lack it | Analyst value | Exec value | ASM differentiation |
|-----------|----------------------|---------------|------------|---------------------|
| Exposure diff (project memory) | scanners are stateless per run | "what changed" focus | trend/posture over time | continuous ASM, not one-shot |
| Asset criticality | scanners rank findings, not assets | triage by what matters | "protect the crown jewels" | business-aware prioritization |
| Adversary simulation | scanners list CVEs | attacker's-eye next steps | real-world risk story | threat-intel framing |
| Security posture | scanners output finding lists | one-number health | board-level metric | analytics platform feel |
| Visual attack surface | scanners output tables | see relationships | one-glance exposure | ASM visualization |
| Interface intelligence | scanners don't classify UIs | find the juicy panels fast | "we expose Jenkins!" | recon-grade insight |
| AI research analyst | scanners have no reasoning | "what to investigate next" | plain-language insight | analyst augmentation |

## 11. Future Roadmap

- Multi-scan trend charts (sparklines) embedded in the report.
- Diff-aware alerting (notify on newly introduced critical exposure).
- ATT&CK Navigator layer export; STIX feed for adversary attribution.
- Real headless screenshots by default (bundled chromium) with AI image classification.
- Asset ownership / business-unit tagging for true business-impact scoring.
- Continuous mode (scheduled re-scan + delta reports).

## Verification
29-engine pipeline runs end-to-end with **zero engine errors**; posture, criticality,
exposure deltas (baseline), adversary view, AI research, and the SVG/HTML attack-surface
map all generated. 19 unit tests pass (added recon-diff, criticality/posture bands).
