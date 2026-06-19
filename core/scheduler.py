"""Bounded async worker pools per resource class + concurrency helpers."""
from __future__ import annotations

import asyncio
from typing import Awaitable, Callable, Iterable, TypeVar

T = TypeVar("T")
R = TypeVar("R")


class Scheduler:
    def __init__(self, concurrency: dict[str, int]):
        self._sems = {
            kind: asyncio.Semaphore(max(n, 1)) for kind, n in concurrency.items()
        }

    def pool(self, kind: str) -> asyncio.Semaphore:
        if kind not in self._sems:
            self._sems[kind] = asyncio.Semaphore(8)
        return self._sems[kind]

    async def map(
        self,
        kind: str,
        func: Callable[[T], Awaitable[R]],
        items: Iterable[T],
    ) -> list[R]:
        """Run func over items bounded by the named pool. Errors -> None."""
        sem = self.pool(kind)

        async def _run(item: T) -> R | None:
            async with sem:
                try:
                    return await func(item)
                except Exception:
                    return None

        tasks = [asyncio.create_task(_run(i)) for i in items]
        if not tasks:
            return []
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]
