"""ScanContext: shared per-scan state passed to every engine."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .bus import EventBus
from .cache import Cache
from .config import Config
from .metrics import MetricsSink
from .models import ToolSource
from .ratelimit import RateLimiter
from .scheduler import Scheduler
from .scope import Scope
from .store import Store


@dataclass
class ScanContext:
    scan_id: str
    scope: Scope
    config: Config
    store: Store
    bus: EventBus
    scheduler: Scheduler
    ratelimiter: RateLimiter
    cache: Cache
    metrics: MetricsSink
    adapters: Any  # AdapterRegistry (avoid import cycle)
    payloads: Any  # PayloadSelector
    logger: logging.Logger
    artifacts_dir: Path
    started_at: datetime

    def source(self, name: str, version: str = "1.0") -> ToolSource:
        return ToolSource(name=name, version=version)

    def in_scope(self, target: str) -> bool:
        return self.scope.is_in_scope(target)
