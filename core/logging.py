"""Diagnostic logging plane (file). Distinct from the UX dashboard plane."""
from __future__ import annotations

import json
import logging
from pathlib import Path


def setup_logging(scan_dir: Path, debug: bool = False) -> logging.Logger:
    scan_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("vulnax")
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    logger.handlers.clear()

    fh = logging.FileHandler(scan_dir / "run.log", encoding="utf-8")
    fh.setFormatter(_JsonFormatter())
    logger.addHandler(fh)

    if debug:
        ch = logging.StreamHandler()
        ch.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
        logger.addHandler(ch)

    logger.propagate = False
    return logger


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)
