#!/usr/bin/env python3
"""VulnaX-Pro — Enterprise Vulnerability Assessment Framework.

Single entry point. Authorized assessment only.

    python main.py scan -d example.com --profile standard
    python main.py scan --scope config/scope.yaml
    python main.py doctor
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

# Make console output UTF-8 safe on Windows legacy consoles.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

from core.config import load_config, load_env_file  # noqa: E402

load_env_file(ROOT / ".env")  # make API keys available before anything else
from core.errors import ScopeError, ConfigError  # noqa: E402
from core.kernel import build_context, build_pipeline, build_scan_id  # noqa: E402
from core.scope import load_scope  # noqa: E402

app = typer.Typer(add_completion=False, help="VulnaX-Pro vulnerability framework")
console = Console()


@app.command()
def scan(
    domain: str = typer.Option(None, "-d", "--domain", help="Single root domain"),
    scope: str = typer.Option(None, "--scope", help="Scope YAML file"),
    profile: str = typer.Option("standard", "--profile",
                                help="quick|standard|deep|stealth"),
    only: str = typer.Option(None, "--only", help="Comma-separated engine names"),
    skip: str = typer.Option(None, "--skip", help="Comma-separated engine names"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Disable AI analyst"),
    active: bool = typer.Option(False, "--active",
                                help="Enable active validators (dalfox/sqlmap) - "
                                     "authorized targets only"),
    no_cache: bool = typer.Option(False, "--no-cache"),
    debug: bool = typer.Option(False, "--debug", help="Reveal diagnostic plane"),
):
    """Run a full assessment pipeline."""
    try:
        sc = load_scope(scope, domain)
    except ScopeError as exc:
        console.print(f"[red]Scope error:[/] {exc}")
        raise typer.Exit(1)

    overrides: dict = {}
    if no_ai:
        overrides["ai"] = {"enabled": False}
    if active:
        overrides["assessment"] = {"active": True}
    try:
        cfg = load_config(profile=profile, overrides=overrides)
    except ConfigError as exc:
        console.print(f"[red]Config error:[/] {exc}")
        raise typer.Exit(1)

    only_set = set(only.split(",")) if only else None
    skip_set = set(skip.split(",")) if skip else set()

    exit_code = asyncio.run(_run_scan(sc, cfg, only_set, skip_set, debug, no_cache))
    raise typer.Exit(exit_code)


async def _run_scan(sc, cfg, only_set, skip_set, debug, no_cache) -> int:
    from utils.ux.dashboard import Dashboard

    scan_id = build_scan_id()
    ctx = build_context(sc, cfg, scan_id=scan_id, debug=debug, no_cache=no_cache)
    scope_label = ", ".join(sc.roots)[:48]

    console.print(f"[cyan]VulnaX-Pro[/] starting scan [bold]{scan_id}[/] "
                  f"· profile {cfg.get('profile')} · scope {scope_label}")

    # Healthcheck (curated, not raw).
    health = await ctx.adapters.healthcheck_all()
    avail = [h.name for h in health if h.available]
    console.print(f"[dim]External accelerators available: "
                  f"{', '.join(avail) if avail else 'none - using pure-Python baselines'}[/]")

    dashboard = Dashboard(ctx.bus, scan_id, scope_label)
    dashboard.start()

    pipeline = build_pipeline()
    try:
        await pipeline.run(ctx, only=only_set, skip=skip_set)
    except KeyboardInterrupt:
        ctx.logger.warning("Interrupted — persisting partial results")
    finally:
        dashboard.stop()

    if not dashboard._live:  # non-TTY: print summary
        dashboard.print_summary()

    paths = getattr(ctx.store, "_report_paths", {})
    console.print("\n[green]Scan complete.[/] Reports:")
    for fmt, p in paths.items():
        console.print(f"  [bold]{fmt.upper()}[/]: {p}")

    # Exit code reflects worst severity.
    findings = [f for f in ctx.store.findings() if f.status == "validated"]
    high = any(f.severity.value in ("critical", "high") for f in findings)
    return 2 if high else 0


@app.command()
def doctor():
    """Check tool availability and environment."""
    cfg = load_config()
    from core.logging import setup_logging
    from integrations.registry import build_registry

    logger = setup_logging(ROOT / "artifacts" / "doctor", debug=False)
    registry = build_registry(cfg, logger)
    table = Table(title="VulnaX-Pro - Tool Health")
    table.add_column("Tool"); table.add_column("Status"); table.add_column("Version")
    results = asyncio.run(registry.healthcheck_all())
    for h in results:
        status = "[green]available[/]" if h.available else "[yellow]missing[/]"
        table.add_row(h.name, status, h.version if h.available else h.detail)
    console.print(table)
    console.print("[dim]Missing tools are optional - engines use pure-Python "
                  "baselines.[/]")

    # AI providers.
    from integrations.llm.providers import _make_provider

    ai = cfg.get("ai", {})
    ai_table = Table(title="AI Providers (key present?)")
    ai_table.add_column("Provider"); ai_table.add_column("Status")
    ai_table.add_column("Model")
    for name in ai.get("priority", []):
        pcfg = ai.get("providers", {}).get(name, {})
        prov = _make_provider(name, pcfg)
        ok = bool(prov and prov.available)
        ai_table.add_row(
            name, "[green]key set[/]" if ok else "[yellow]no key[/]",
            pcfg.get("model", "-"))
    console.print(ai_table)
    console.print(f"[dim]AI selection: {ai.get('provider','auto')} "
                  f"(priority: {', '.join(ai.get('priority', []))}). "
                  "No key anywhere -> offline fallback summaries.[/]")


@app.command()
def version():
    """Show framework version."""
    console.print("VulnaX-Pro 1.0.0")


if __name__ == "__main__":
    app()
