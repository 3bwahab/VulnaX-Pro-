"""Per-engine execution metrics."""
from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass, field


@dataclass
class EngineMetric:
    name: str
    duration_s: float = 0.0
    produced: int = 0
    errors: int = 0
    status: str = "pending"


class MetricsSink:
    def __init__(self) -> None:
        self.engines: dict[str, EngineMetric] = {}

    @contextmanager
    def time_engine(self, name: str):
        m = EngineMetric(name=name, status="running")
        self.engines[name] = m
        start = time.monotonic()
        try:
            yield m
            m.status = "ok"
        except Exception:
            m.status = "error"
            m.errors += 1
            raise
        finally:
            m.duration_s = round(time.monotonic() - start, 2)

    def as_dict(self) -> dict:
        return {
            k: {
                "duration_s": m.duration_s,
                "produced": m.produced,
                "errors": m.errors,
                "status": m.status,
            }
            for k, m in self.engines.items()
        }
