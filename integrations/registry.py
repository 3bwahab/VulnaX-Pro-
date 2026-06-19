"""Adapter registry: discovery by capability + healthchecks."""
from __future__ import annotations

from .base import Capability, ToolAdapter
from .tools import ALL_ADAPTERS


class AdapterRegistry:
    def __init__(self, adapters: list[ToolAdapter]):
        self._adapters = adapters

    def by_capability(self, cap: Capability) -> list[ToolAdapter]:
        return [a for a in self._adapters if cap in a.capabilities]

    def available(self, cap: Capability) -> list[ToolAdapter]:
        return [a for a in self.by_capability(cap) if a.is_available()]

    def get(self, name: str) -> ToolAdapter | None:
        return next((a for a in self._adapters if a.name == name), None)

    async def healthcheck_all(self) -> list:
        results = []
        for a in self._adapters:
            results.append(await a.healthcheck())
        return results

    @property
    def all(self) -> list[ToolAdapter]:
        return list(self._adapters)


def build_registry(config, logger) -> AdapterRegistry:
    adapters = [cls(config, logger) for cls in ALL_ADAPTERS]
    return AdapterRegistry(adapters)
