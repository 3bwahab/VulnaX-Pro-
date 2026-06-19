"""CVEIntelligenceEngine (Stage 5): map detected products+versions to known CVEs.

Ships a small offline dataset; extendable via config/cve_dataset.json. Real
deployments sync NVD/OSV/KEV/EPSS via `python main.py tools update`.
"""
from __future__ import annotations

import json
from pathlib import Path

from core.models import CVEMatch
from utils.version import version_lte, version_lt

from .base import Engine

# Minimal illustrative dataset: product -> list of advisories.
# match: {"max_exclusive": "1.20.1"} or {"max_inclusive": "5.7.1"}
BUILTIN_DATASET = {
    "nginx": [
        {"cve": "CVE-2021-23017", "cvss": 7.7, "epss": 0.12, "kev": False,
         "max_exclusive": "1.20.1", "desc": "DNS resolver off-by-one heap write"},
    ],
    "apache": [
        {"cve": "CVE-2021-41773", "cvss": 7.5, "epss": 0.94, "kev": True,
         "max_inclusive": "2.4.49", "desc": "Path traversal / RCE"},
        {"cve": "CVE-2021-42013", "cvss": 9.8, "epss": 0.95, "kev": True,
         "max_inclusive": "2.4.50", "desc": "Path traversal / RCE"},
    ],
    "wordpress": [
        {"cve": "CVE-2022-21661", "cvss": 8.0, "epss": 0.2, "kev": False,
         "max_exclusive": "5.8.3", "desc": "WP_Query SQL injection"},
    ],
    "php": [
        {"cve": "CVE-2019-11043", "cvss": 9.8, "epss": 0.96, "kev": True,
         "max_exclusive": "7.3.11", "desc": "php-fpm RCE"},
    ],
}


class CVEIntelligenceEngine(Engine):
    name = "cve_intelligence"
    stage = 7
    depends_on = ("technology_detection", "service_fingerprint")

    async def run(self, ctx) -> None:
        dataset = self._load_dataset()
        matches = 0
        for tech in ctx.store.technologies():
            if not tech.version:
                continue
            key = tech.name.lower()
            advisories = dataset.get(key)
            if not advisories:
                continue
            for adv in advisories:
                if self._affected(tech.version, adv):
                    ctx.store.add(CVEMatch(
                        cve_id=adv["cve"], asset_id=tech.asset_id,
                        technology_id=tech.id, product=tech.name,
                        cvss=adv.get("cvss"), epss=adv.get("epss"),
                        kev=adv.get("kev", False),
                        affected_range=self._range_str(adv),
                        match_type="range", confidence=0.7))
                    matches += 1
        ctx.logger.info("CVE intelligence: %d matches", matches)

    def _affected(self, version: str, adv: dict) -> bool:
        if "max_exclusive" in adv:
            return version_lt(version, adv["max_exclusive"])
        if "max_inclusive" in adv:
            return version_lte(version, adv["max_inclusive"])
        return False

    def _range_str(self, adv: dict) -> str:
        if "max_exclusive" in adv:
            return f"< {adv['max_exclusive']}"
        if "max_inclusive" in adv:
            return f"<= {adv['max_inclusive']}"
        return "unknown"

    def _load_dataset(self) -> dict:
        data = dict(BUILTIN_DATASET)
        ext = Path(__file__).resolve().parent.parent / "config" / "cve_dataset.json"
        if ext.exists():
            try:
                user = json.loads(ext.read_text(encoding="utf-8"))
                for k, v in user.items():
                    data.setdefault(k.lower(), []).extend(v)
            except Exception:
                pass
        return data
