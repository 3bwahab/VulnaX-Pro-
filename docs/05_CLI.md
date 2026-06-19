# 05 — CLI Architecture & User Experience

## 1. Principles

- Single entry point: `python main.py`.
- Feels like a **commercial enterprise product**, not a wrapper script.
- The user **never** sees raw tool output (`Running subfinder...`) on the console.
- Output is a curated, live dashboard of meaningful metrics.

## 2. Command Surface (Typer)

```
python main.py scan      --scope config/scope.yaml --profile standard
python main.py scan      -d example.com --profile quick
python main.py resume    --scan-id 2026-06-15-ab12
python main.py report    --scan-id 2026-06-15-ab12 --format html,md,json
python main.py inventory --scan-id ...            # asset inventory only
python main.py doctor                              # tool/version healthcheck
python main.py tools     update                    # sync templates/wordlists/CVE
python main.py config    show|validate
```

### Key flags for `scan`
```
--scope PATH            (required unless -d) scope file
-d, --domain TEXT       quick single-root scope
--profile {quick,standard,deep,stealth}
--only / --skip ENGINE  run/skip specific engines
--concurrency INT       global worker cap override
--rate INT              global RPS override
--no-ai                 disable AIAnalystEngine
--output DIR            result bundle location
--resume                continue from cache
--verbose / --debug     reveal diagnostic plane (raw logs)
```

## 3. The Live Dashboard (`utils/ux/dashboard.py`)

Rich-based live view subscribed to the event bus. Layout:

```
╔══════════════════════════════════════════════════════════════════════╗
║  VulnaX-Pro   ·   scan 2026-06-15-ab12   ·   scope: *.example.com      ║
╠══════════════════════════════════════════════════════════════════════╣
║  [DISCOVERY]            Assets Found ............... 1,248             ║
║  [VALIDATION]           Live Assets ...............   384             ║
║  [FINGERPRINTING]       Technologies Identified ...   127             ║
║  [CRAWLING]             URLs Collected ............ 14,532             ║
║  [JAVASCRIPT ANALYSIS]  Files Analyzed ............   921             ║
║  [API DISCOVERY]        Endpoints Identified ......  3,241             ║
║  [VULNERABILITY]        Validated Findings ........    18             ║
║  [ATTACK PATHS]         Critical Paths ............     3             ║
╠══════════════════════════════════════════════════════════════════════╣
║  Stage 4/8  INTEL  ▓▓▓▓▓▓▓▓▓▓▓░░░░  68%   elapsed 04:12   eta 01:55    ║
║  Top finding: [CRITICAL] Exposed .git on api.example.com  (conf 0.97)  ║
╚══════════════════════════════════════════════════════════════════════╝
```

Behavior:
- Counters update live from bus events (`AssetFound`, `UrlCollected`, …).
- Current stage shows a progress bar + ETA from scheduler metrics.
- A rolling "top finding" ticker surfaces the highest-risk validated finding.
- On completion: a summary panel + report file paths.

## 4. Output Plane Separation

| Plane | Destination | Content |
|-------|-------------|---------|
| UX | console (Rich) | curated counters, progress, findings |
| Diagnostic | `artifacts/<scan_id>/run.log` (JSONL) | full commands, stderr, traces |

`--verbose` mirrors warnings to console; `--debug` mirrors the diagnostic plane.
Default console is clean and enterprise-grade.

## 5. Non-TTY / CI Mode

When stdout is not a TTY (piped/CI), the dashboard degrades to periodic structured
status lines (one JSON object per stage) — still no raw tool spew. Exit code
reflects outcome: `0` clean, `2` findings ≥ High, `1` execution error.

## 6. Startup Flow

```
main.py
  → parse args (Typer)
  → load + validate config (profile merge)
  → load + validate scope (abort if missing/invalid)
  → build kernel (store, scheduler, registry, ux)
  → registry.healthcheck_all()  → warn on missing tools
  → pipeline.run(ctx)           → dashboard live
  → reporting outputs           → print report paths
  → exit code by severity
```

## 7. Accessibility & Polish

- Color theme in `utils/ux/theme.py` (severity colors, brandable).
- `--no-color` and `NO_COLOR` env respected.
- Graceful Ctrl-C: cancels tasks, persists partial results, still renders a report.
