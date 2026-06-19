"""Application kernel: assembles context, adapters, and the engine pipeline."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

from .bus import EventBus
from .cache import Cache
from .config import Config
from .context import ScanContext
from .logging import setup_logging
from .metrics import MetricsSink
from .pipeline import Pipeline
from .ratelimit import RateLimiter
from .scheduler import Scheduler
from .scope import Scope
from .store import Store

ROOT = Path(__file__).resolve().parent.parent


def build_scan_id() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:4]


def build_context(
    scope: Scope,
    config: Config,
    scan_id: str | None = None,
    debug: bool = False,
    no_cache: bool = False,
) -> ScanContext:
    from integrations.registry import build_registry
    from payload_intelligence.selector import PayloadSelector

    scan_id = scan_id or build_scan_id()
    artifacts_dir = ROOT / "artifacts" / scan_id
    cache_dir = ROOT / "cache"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    logger = setup_logging(artifacts_dir, debug=debug)
    bus = EventBus()
    store = Store(artifacts_dir)
    scheduler = Scheduler(config.get("concurrency", {}))

    rate = config.get("rate", {})
    if scope.rate:
        rate = {**rate, **scope.rate}
    ratelimiter = RateLimiter(
        global_rps=rate.get("global_rps", 50),
        per_host_rps=rate.get("per_host_rps", 10),
    )
    cache = Cache(cache_dir, enabled=not no_cache)
    metrics = MetricsSink()
    adapters = build_registry(config, logger)
    payloads = PayloadSelector(ROOT, logger)

    return ScanContext(
        scan_id=scan_id,
        scope=scope,
        config=config,
        store=store,
        bus=bus,
        scheduler=scheduler,
        ratelimiter=ratelimiter,
        cache=cache,
        metrics=metrics,
        adapters=adapters,
        payloads=payloads,
        logger=logger,
        artifacts_dir=artifacts_dir,
        started_at=datetime.now(timezone.utc),
    )


def build_pipeline() -> Pipeline:
    from engines import all_engines

    return Pipeline([cls() for cls in all_engines()])
