"""Token-bucket rate limiting: global + per-host."""
from __future__ import annotations

import asyncio
import time
from collections import defaultdict


class _Bucket:
    def __init__(self, rps: float):
        self.rps = max(rps, 0.1)
        self.capacity = max(rps, 1.0)
        self.tokens = self.capacity
        self.updated = time.monotonic()
        self.lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self.lock:
            while True:
                now = time.monotonic()
                self.tokens = min(
                    self.capacity, self.tokens + (now - self.updated) * self.rps
                )
                self.updated = now
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                await asyncio.sleep((1.0 - self.tokens) / self.rps)


class RateLimiter:
    def __init__(self, global_rps: float = 50, per_host_rps: float = 10):
        self._global = _Bucket(global_rps)
        self._per_host_rps = per_host_rps
        self._hosts: dict[str, _Bucket] = defaultdict(
            lambda: _Bucket(per_host_rps)
        )

    async def acquire(self, host: str | None = None) -> None:
        await self._global.acquire()
        if host:
            await self._hosts[host].acquire()
