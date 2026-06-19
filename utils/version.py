"""Lightweight semver-ish comparison for version intelligence."""
from __future__ import annotations

import re

_NUM = re.compile(r"\d+")


def _parts(v: str) -> list[int]:
    return [int(x) for x in _NUM.findall(v or "")] or [0]


def version_cmp(a: str, b: str) -> int:
    pa, pb = _parts(a), _parts(b)
    for x, y in zip(pa, pb):
        if x != y:
            return -1 if x < y else 1
    if len(pa) != len(pb):
        return -1 if len(pa) < len(pb) else 1
    return 0


def version_lt(a: str, b: str) -> bool:
    return version_cmp(a, b) < 0


def version_lte(a: str, b: str) -> bool:
    return version_cmp(a, b) <= 0
