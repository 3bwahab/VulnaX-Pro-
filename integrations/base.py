"""Adapter contract. Engines call adapters by capability, never tools directly."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

from pydantic import BaseModel

from .process import run_process, which

# Match a version like v1.2.3 / 1.2 but NOT an IP octet (negative lookahead on .N).
_VERSION_RE = re.compile(r"v?\d+\.\d+(?:\.\d+)?(?:[-\w.]*)?(?!\.\d)")


def _parse_version(stdout: str, stderr: str) -> str:
    """Pull a clean vX.Y.Z out of a tool's banner / version output."""
    for blob in (stdout, stderr):
        for line in blob.splitlines():
            m = _VERSION_RE.search(line)
            if m:
                return m.group(0)
    # fall back to first line that mentions "version"
    for blob in (stdout, stderr):
        for line in blob.splitlines():
            if "version" in line.lower() and line.strip():
                return line.strip()[:40]
    return "installed"


class Capability(Enum):
    SUBDOMAIN_ENUM = auto()
    DNS_RESOLVE = auto()
    PORT_SCAN = auto()
    HTTP_PROBE = auto()
    CRAWL = auto()
    CONTENT_DISCOVERY = auto()
    TEMPLATE_SCAN = auto()
    TECH_FINGERPRINT = auto()
    XSS_SCAN = auto()
    SQLI_SCAN = auto()
    SCREENSHOT = auto()


@dataclass
class AdapterHealth:
    name: str
    available: bool
    version: str = "n/a"
    detail: str = ""


@dataclass
class ToolRequest:
    targets: list[str]
    options: dict[str, Any] = field(default_factory=dict)
    timeout_s: float = 120.0


@dataclass
class AdapterResult:
    models: list[BaseModel] = field(default_factory=list)
    raw: str = ""
    returncode: int = 0
    errors: list[str] = field(default_factory=list)


class ToolAdapter:
    """Base for external-tool adapters. Subclasses set name/binary/capabilities."""

    name: str = "abstract"
    binary: str = ""
    capabilities: set[Capability] = set()
    version_args: list[str] = ["-version"]

    def __init__(self, config, logger):
        self.config = config
        self.logger = logger

    def is_available(self) -> bool:
        return bool(self.binary) and which(self.binary) is not None

    async def healthcheck(self) -> AdapterHealth:
        if not self.is_available():
            return AdapterHealth(self.name, False, detail="binary not found")
        try:
            res = await run_process([self.binary, *self.version_args], timeout=15)
            return AdapterHealth(self.name, True,
                                 version=_parse_version(res.stdout, res.stderr))
        except Exception as exc:  # noqa: BLE001
            return AdapterHealth(self.name, False, detail=str(exc))

    async def run(self, request: ToolRequest) -> AdapterResult:  # pragma: no cover
        raise NotImplementedError

    def normalize(self, raw: str, request: ToolRequest) -> list[BaseModel]:
        return []
