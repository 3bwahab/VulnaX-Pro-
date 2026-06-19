"""Pipeline: runs engines in dependency order, concurrently within a stage."""
from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from engines.base import Engine
    from .context import ScanContext


class Pipeline:
    def __init__(self, engines: list["Engine"]):
        self.engines = engines

    def _stages(self, only: set[str] | None, skip: set[str]) -> list[list["Engine"]]:
        selected = [
            e for e in self.engines
            if (only is None or e.name in only) and e.name not in skip
        ]
        by_stage: dict[int, list["Engine"]] = defaultdict(list)
        for e in selected:
            by_stage[e.stage].append(e)
        return [by_stage[s] for s in sorted(by_stage)]

    async def run(
        self,
        ctx: "ScanContext",
        only: set[str] | None = None,
        skip: set[str] | None = None,
    ) -> None:
        import asyncio

        skip = skip or set()
        for stage_engines in self._stages(only, skip):
            # Engines within a stage run concurrently; each fans out internally.
            await asyncio.gather(
                *(self._run_engine(e, ctx) for e in stage_engines)
            )

    async def _run_engine(self, engine: "Engine", ctx: "ScanContext") -> None:
        ctx.bus.emit("stage_started", engine=engine.name, stage=engine.stage)
        with ctx.metrics.time_engine(engine.name) as metric:
            try:
                await engine.preflight(ctx)
                await engine.run(ctx)
            except Exception as exc:
                ctx.logger.exception("Engine %s failed: %s", engine.name, exc)
                metric.errors += 1
                if not engine.optional:
                    ctx.bus.emit("engine_error", engine=engine.name, error=str(exc))
                # Pipeline continues regardless — partial results are preserved.
            finally:
                try:
                    await engine.teardown(ctx)
                except Exception:
                    pass
        ctx.bus.emit("stage_completed", engine=engine.name)
