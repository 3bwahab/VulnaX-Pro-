# VulnaX-Pro

**Enterprise Vulnerability Assessment Framework** — a standalone, single-process
Python platform for *authorized* attack-surface discovery, vulnerability
correlation, attack-path analysis, and commercial-grade reporting.

```bash
python main.py scan --scope config/scope.yaml --profile standard
```

> Runs entirely locally. No SaaS, no web app, no microservices, no database server,
> no Docker/Kubernetes dependency. Everything executes from one Python process.

## Status

**Design phase.** The complete architecture specification (the 16 required
deliverables) lives in [`docs/`](docs/). Implementation follows the roadmap in
`docs/12_SCALING_TESTING_ROADMAP.md`.

## Design Library

| Doc | Covers |
|-----|--------|
| [00_OVERVIEW](docs/00_OVERVIEW.md) | Scope, pillars, optimization targets, doc map |
| [01_DIRECTORY_STRUCTURE](docs/01_DIRECTORY_STRUCTURE.md) | Full on-disk layout |
| [02_ARCHITECTURE](docs/02_ARCHITECTURE.md) | Layers, kernel, pipeline, scope guard |
| [03_ENGINES](docs/03_ENGINES.md) | Engine-by-engine design (all 16) |
| [04_INTEGRATIONS](docs/04_INTEGRATIONS.md) | Tool adapter layer |
| [05_CLI](docs/05_CLI.md) | CLI + live enterprise dashboard UX |
| [06_DATA_MODELS](docs/06_DATA_MODELS.md) | Typed models + result schemas |
| [07_PAYLOAD_INTELLIGENCE](docs/07_PAYLOAD_INTELLIGENCE.md) | Resource selection engine |
| [08_REPORTING](docs/08_REPORTING.md) | Multi-format reporting |
| [09_ATTACK_PATH](docs/09_ATTACK_PATH.md) | Surface graph + attack paths |
| [10_DIAGRAMS](docs/10_DIAGRAMS.md) | Mermaid + execution-flow diagrams |
| [11_PLUGINS](docs/11_PLUGINS.md) | Plugin architecture |
| [12_SCALING_TESTING_ROADMAP](docs/12_SCALING_TESTING_ROADMAP.md) | Scaling, testing, roadmap |

## Core Engines (16)

AssetDiscovery · AssetValidation · ServiceFingerprint · TechnologyDetection ·
DeepCrawler · JavaScriptIntelligence · ApiDiscovery · AuthenticationMapping ·
ConfigurationAssessment · VulnerabilityCorrelation · CVEIntelligence ·
AttackSurfaceGraph · RiskScoring · AttackPath · AIAnalyst · Reporting.

## Integrated Tools (via unified adapters)

subfinder · amass · assetfinder · findomain · chaos · naabu · httpx · dnsx ·
katana · nuclei · feroxbuster · dirsearch · wappalyzer.

## Principles

- Engine independence · tool abstraction · asyncio-first · evidence-driven findings.
- Fast discovery → fast validation → fast correlation; low false positives;
  professional presentation.
- Never generates payloads — *selects* optimal SecLists / Nuclei resources by
  detected technology.

## Authorization

For authorized testing only (bug-bounty scope, owned assets, engagements with
written permission). A valid scope file is mandatory; out-of-scope targets are
refused at the integration layer.
