"""Retry policy with exponential backoff and jitter."""
from __future__ import annotations

import asyncio
import random
from typing import Awaitable, Callable, TypeVar

T = TypeVar("T")


async def with_retry(
    coro_factory: Callable[[], Awaitable[T]],
    attempts: int = 2,
    backoff: float = 0.4,
    jitter: float = 0.2,
    retry_on: tuple[type[Exception], ...] = (Exception,),
) -> T:
    last: Exception | None = None
    for i in range(max(attempts, 1)):
        try:
            return await coro_factory()
        except retry_on as exc:  # noqa: PERF203
            last = exc
            if i == attempts - 1:
                break
            delay = backoff * (2 ** i) + random.uniform(0, jitter)
            await asyncio.sleep(delay)
    assert last is not None
    raise last
