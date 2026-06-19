"""Live enterprise dashboard. The user sees curated metrics, never raw tool output."""
from __future__ import annotations

import asyncio
import sys

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# (counter key, section label, metric label)
SECTIONS = [
    ("assets_found", "DISCOVERY", "Assets Found"),
    ("live_assets", "VALIDATION", "Live Assets"),
    ("services", "SERVICE DISCOVERY", "Services Found"),
    ("technologies", "FINGERPRINTING", "Technologies Identified"),
    ("urls", "CRAWLING", "URLs Collected"),
    ("js_files", "JAVASCRIPT ANALYSIS", "Files Analyzed"),
    ("api_endpoints", "API DISCOVERY", "Endpoints Identified"),
    ("parameters", "PARAMETER INTELLIGENCE", "Parameters Catalogued"),
    ("findings", "VULNERABILITY ANALYSIS", "Validated Findings"),
    ("critical_paths", "ATTACK PATH ANALYSIS", "Critical Paths"),
    ("mitre_techniques", "MITRE ANALYSIS", "Techniques Mapped"),
    ("mitre_tactics", "MITRE ANALYSIS", "Tactics Mapped"),
    ("adversary_paths", "MITRE ANALYSIS", "Adversary Paths Generated"),
    ("threat_scenarios", "MITRE ANALYSIS", "Threat Scenarios Generated"),
    ("mitre_coverage", "MITRE ANALYSIS", "ATT&CK Coverage %"),
    ("interfaces", "INTERFACE INTELLIGENCE", "Notable Interfaces"),
    ("exposure_changes", "EXPOSURE INTELLIGENCE", "Changes vs Last Scan"),
    ("posture_score", "SECURITY POSTURE", "Posture Score (0-100)"),
]

_SEV_COLOR = {
    "critical": "bold white on red", "high": "bold red",
    "medium": "yellow", "low": "cyan", "info": "dim",
}


class Dashboard:
    def __init__(self, bus, scan_id: str, scope_label: str):
        self.bus = bus
        self.scan_id = scan_id
        self.scope_label = scope_label
        self.console = Console()
        self.current_stage = "initializing"
        self.top_finding: str | None = None
        self._live: Live | None = None
        self._task: asyncio.Task | None = None
        bus.subscribe("stage_started", self._on_stage)
        bus.subscribe("top_finding", self._on_top)

    def _on_stage(self, ev) -> None:
        self.current_stage = ev.data.get("engine", "")

    def _on_top(self, ev) -> None:
        sev = ev.data.get("severity", "info")
        color = _SEV_COLOR.get(sev, "white")
        self.top_finding = f"[{color}][{sev.upper()}][/] {ev.data.get('title','')}"

    def _render(self):
        table = Table.grid(padding=(0, 2))
        table.add_column(justify="left")
        table.add_column(justify="left")
        table.add_column(justify="right")
        counters = self.bus.counters
        for key, section, label in SECTIONS:
            val = counters.get(key, 0)
            table.add_row(
                Text(f"[{section}]", style="bold cyan"),
                Text(label, style="white"),
                Text(f"{val:,}", style="bold green"),
            )
        footer = Text(f"Stage: {self.current_stage}", style="bold magenta")
        if self.top_finding:
            footer = Group(footer, Text.from_markup(f"Top: {self.top_finding}"))
        body = Group(table, Text(""), footer)
        return Panel(
            body,
            title=f"[bold]VulnaX-Pro[/]  ·  scan {self.scan_id}  ·  {self.scope_label}",
            border_style="cyan",
        )

    async def _loop(self) -> None:
        try:
            while True:
                if self._live:
                    self._live.update(self._render())
                await asyncio.sleep(0.4)
        except asyncio.CancelledError:
            pass

    def start(self) -> None:
        if not sys.stdout.isatty():
            return  # non-TTY: stay quiet, summary printed at end
        self._live = Live(self._render(), console=self.console, refresh_per_second=4)
        self._live.start()
        self._task = asyncio.create_task(self._loop())

    def stop(self) -> None:
        if self._task:
            self._task.cancel()
        if self._live:
            self._live.update(self._render())
            self._live.stop()

    def print_summary(self) -> None:
        c = self.bus.counters
        self.console.print(self._render())
