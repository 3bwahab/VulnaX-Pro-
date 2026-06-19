"""Layered configuration loading: defaults -> profile -> CLI overrides -> env."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from .errors import ConfigError

ROOT = Path(__file__).resolve().parent.parent

DEFAULTS: dict[str, Any] = {
    "concurrency": {"http": 30, "dns": 50, "process": 8, "cpu": 4},
    "timeouts": {"http": 12.0, "dns": 5.0, "process": 120.0},
    "rate": {"global_rps": 50, "per_host_rps": 10},
    "retry": {"attempts": 2, "backoff": 0.4, "jitter": 0.2},
    "crawler": {"max_pages": 150, "max_depth": 2},
    "discovery": {"dns_brute": True, "ct_logs": True, "max_brute": 200},
    "ports": {"top": [21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995,
                      1433, 3306, 3389, 5432, 5900, 6379, 8000, 8080,
                      8443, 8888, 9200, 27017]},
    "ai": {"enabled": True, "model": "claude-opus-4-8", "max_findings": 25},
    "report": {"formats": ["html", "md", "json"]},
    "user_agent": "VulnaX-Pro/1.0 (+authorized-assessment)",
}

PROFILES: dict[str, dict[str, Any]] = {
    "quick": {
        "crawler": {"max_pages": 40, "max_depth": 1},
        "discovery": {"dns_brute": False, "max_brute": 50},
        "ports": {"top": [80, 443, 8080, 8443]},
    },
    "standard": {},
    "deep": {
        "crawler": {"max_pages": 400, "max_depth": 3},
        "discovery": {"dns_brute": True, "max_brute": 1000},
        "concurrency": {"http": 50, "dns": 80},
    },
    "stealth": {
        "rate": {"global_rps": 5, "per_host_rps": 2},
        "concurrency": {"http": 5, "dns": 10, "process": 2},
    },
}


def load_env_file(path: Path | str) -> None:
    """Minimal .env loader (no dependency). Does not overwrite existing env vars."""
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = val


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


class Config:
    def __init__(self, data: dict[str, Any]):
        self._d = data

    def get(self, dotted: str, default: Any = None) -> Any:
        cur: Any = self._d
        for part in dotted.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return default
            cur = cur[part]
        return cur

    @property
    def data(self) -> dict[str, Any]:
        return self._d

    def __repr__(self) -> str:
        return f"Config(profile={self._d.get('profile')})"


def load_config(
    profile: str = "standard",
    config_file: str | None = None,
    overrides: dict[str, Any] | None = None,
) -> Config:
    data = dict(DEFAULTS)

    # File config (config/default.yaml) layered on top of code defaults.
    default_yaml = ROOT / "config" / "default.yaml"
    if default_yaml.exists():
        with open(default_yaml, "r", encoding="utf-8") as fh:
            data = _deep_merge(data, yaml.safe_load(fh) or {})

    if config_file:
        p = Path(config_file)
        if not p.exists():
            raise ConfigError(f"Config file not found: {config_file}")
        with open(p, "r", encoding="utf-8") as fh:
            data = _deep_merge(data, yaml.safe_load(fh) or {})

    if profile not in PROFILES:
        raise ConfigError(f"Unknown profile '{profile}'. Choices: {list(PROFILES)}")
    data = _deep_merge(data, PROFILES[profile])
    data["profile"] = profile

    # Environment overrides (VULNAX_RATE_GLOBAL_RPS=... etc) — simple flat keys.
    for key, val in os.environ.items():
        if key.startswith("VULNAX_"):
            data.setdefault("_env", {})[key] = val

    if overrides:
        data = _deep_merge(data, overrides)

    return Config(data)
