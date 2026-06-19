# Project Anatomy — VulnaX-Pro

> Read this before opening project files. Updated after every write/edit.

## What this project is
VulnaX-Pro: a standalone single-process Python vulnerability assessment framework.
Entry point `python main.py`. Orchestrates security tools behind a unified engine
architecture. **Implemented and runs end-to-end** (Python 3.11). Each engine has a
pure-Python baseline so it works with zero external tools; subfinder/httpx/katana/
naabu/nuclei are optional accelerators (detected via `python main.py doctor`).

## Current on-disk state
```
main.py                    # Typer CLI: scan / doctor / version
core/                      # kernel: models, store, config, scope, scheduler,
                           #   bus, ratelimit, retry, cache, metrics, pipeline, kernel
integrations/              # process runner, base adapter, registry, tools.py
                           #   (subfinder/httpx/naabu/katana/nuclei adapters)
engines/                   # 29 engines (see all_engines() in __init__.py)
                           #   ASM layer (stage15-16): asset_criticality,
                           #   exposure_intelligence, api_relationship,
                           #   interface_intelligence, security_posture,
                           #   adversary_simulation, visual_attack_surface
core/confidence.py         # multi-stage confidence model (4 bands)
core/orchestration.py      # AssessmentPlan + ValidationOrchestrator (active gated)
core/recon_memory.py       # project snapshots + diff + trends (recon_memory/)
mitre/                     # ATT&CK layer: knowledge_base.py, mapping.py,
                           #   data/attack_core.json (offline curated KB, 34 tech/14 tactics)
payload_intelligence/      # catalog, selector, profiles/*.yaml
utils/                     # net, text, version, http (HttpClient), ux/dashboard
config/                    # default.yaml, scope.example.yaml
tests/test_core.py         # offline unit tests (10, all pass)
requirements.txt
README.md                  # project intro + design library index
docs/                      # THE deliverables (architecture spec, 16 parts)
  00_OVERVIEW.md
  01_DIRECTORY_STRUCTURE.md
  02_ARCHITECTURE.md
  03_ENGINES.md            # engine-by-engine design (16 engines)
  04_INTEGRATIONS.md       # tool adapter layer
  05_CLI.md                # CLI + live dashboard UX
  06_DATA_MODELS.md        # typed models + result schemas
  07_PAYLOAD_INTELLIGENCE.md
  08_REPORTING.md
  09_ATTACK_PATH.md        # surface graph + attack paths
  10_DIAGRAMS.md           # mermaid + execution flows
  11_PLUGINS.md
  12_SCALING_TESTING_ROADMAP.md
.wolf/                     # project memory (this folder)
```
No source code (`core/`, `engines/`, etc.) exists yet — the directory tree in
`docs/01_DIRECTORY_STRUCTURE.md` is the *target* layout to build.

## Key design facts (so you don't re-read everything)
- 16 engines arranged as a DAG across 9 stages (0=Discovery .. 8=Reporting).
- Engines never call subprocesses or each other; they go through adapters (by
  capability) and share state via the embedded store (SQLite + artifacts).
- Tools integrated: subfinder, amass, assetfinder, findomain, chaos, naabu, httpx,
  dnsx, katana, nuclei, feroxbuster, dirsearch, wappalyzer.
- Payload Intelligence SELECTS resources (SecLists/Nuclei), never generates them.
- Findings require non-empty structured Evidence (validation invariant).
- AI engine = Claude (default model claude-opus-4-8) on structured evidence only,
  with offline deterministic fallback.
- Mandatory scope file; out-of-scope targets refused at integration layer.

## Where to look for X
- Data contracts / schemas → docs/06_DATA_MODELS.md
- Adapter contract → docs/04_INTEGRATIONS.md
- Pipeline/stages/scope guard → docs/02_ARCHITECTURE.md
- Build order → docs/12_SCALING_TESTING_ROADMAP.md (Part C roadmap)
