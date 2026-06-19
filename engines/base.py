"""Engine ABC + lifecycle contract. Engines never import each other."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.context import ScanContext


class Engine(ABC):
    name: str = "engine"
    stage: int = 0
    depends_on: tuple[str, ...] = ()
    requires_tools: tuple[str, ...] = ()
    optional: bool = True  # default: degrade, don't crash the pipeline

    async def preflight(self, ctx: "ScanContext") -> None:
        return None

    @abstractmethod
    async def run(self, ctx: "ScanContext") -> None: ...

    async def teardown(self, ctx: "ScanContext") -> None:
        return None
