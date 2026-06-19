"""In-process async event bus. Decouples execution from presentation."""
from __future__ import annotations

import asyncio
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class Event:
    name: str
    data: dict[str, Any] = field(default_factory=dict)


class EventBus:
    def __init__(self) -> None:
        self._subs: dict[str, list[Callable[[Event], None]]] = defaultdict(list)
        self._counters: dict[str, int] = defaultdict(int)
        self._lock = asyncio.Lock()

    def subscribe(self, name: str, handler: Callable[[Event], None]) -> None:
        self._subs[name].append(handler)

    def emit(self, name: str, **data: Any) -> None:
        ev = Event(name, data)
        for handler in self._subs.get(name, []):
            try:
                handler(ev)
            except Exception:  # presentation must never break execution
                pass
        for handler in self._subs.get("*", []):
            try:
                handler(ev)
            except Exception:
                pass

    def incr(self, counter: str, by: int = 1) -> int:
        self._counters[counter] += by
        self.emit("counter", counter=counter, value=self._counters[counter])
        return self._counters[counter]

    @property
    def counters(self) -> dict[str, int]:
        return dict(self._counters)
