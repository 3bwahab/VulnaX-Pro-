"""Tech profile -> optimal resource selection (nuclei tags, sensitive paths, lists).

Built-in profiles ship in code so the framework works with zero external wordlists;
additional profiles may be dropped as YAML under payload_intelligence/profiles/.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .catalog import ResourceCatalog

# Baseline sensitive paths checked on every host regardless of tech.
BASELINE_SENSITIVE = [
    "/.git/config", "/.git/HEAD", "/.env", "/.env.local", "/config.json",
    "/.svn/entries", "/.DS_Store", "/backup.zip", "/backup.sql", "/dump.sql",
    "/phpinfo.php", "/server-status", "/.aws/credentials", "/wp-config.php.bak",
    "/.well-known/security.txt", "/robots.txt", "/sitemap.xml",
    "/swagger.json", "/openapi.json", "/api-docs", "/actuator", "/actuator/env",
]

# Built-in technology profiles.
TECH_PROFILES: dict[str, dict] = {
    "laravel": {
        "nuclei_tags": ["laravel", "php", "debug"],
        "sensitive": ["/.env", "/telescope/requests", "/storage/logs/laravel.log",
                      "/_ignition/health-check", "/horizon/api/stats"],
    },
    "wordpress": {
        "nuclei_tags": ["wordpress", "wp-plugin", "wp-theme", "cve"],
        "sensitive": ["/wp-config.php.bak", "/xmlrpc.php", "/wp-json/wp/v2/users",
                      "/wp-login.php", "/wp-content/debug.log"],
    },
    "graphql": {
        "nuclei_tags": ["graphql"],
        "sensitive": ["/graphql", "/graphiql", "/v1/graphql", "/api/graphql"],
    },
    "react": {
        "nuclei_tags": ["exposure", "js"],
        "sensitive": ["/static/js/main.js", "/asset-manifest.json",
                      "/static/js/", "/manifest.json"],
        "strategy": "spa",
    },
    "django": {
        "nuclei_tags": ["django", "python"],
        "sensitive": ["/admin/", "/static/admin/", "/__debug__/"],
    },
    "spring": {
        "nuclei_tags": ["spring", "java", "actuator"],
        "sensitive": ["/actuator", "/actuator/env", "/actuator/heapdump",
                      "/actuator/health"],
    },
    "nginx": {"nuclei_tags": ["nginx"], "sensitive": ["/nginx_status"]},
    "apache": {"nuclei_tags": ["apache"], "sensitive": ["/server-status",
                                                        "/server-info"]},
}


@dataclass
class Selection:
    nuclei_tags: list[str] = field(default_factory=list)
    sensitive_paths: list[str] = field(default_factory=list)
    wordlist: Path | None = None
    strategy: str = "classic"
    rationale: str = ""


class PayloadSelector:
    def __init__(self, root: Path, logger):
        self.root = root
        self.logger = logger
        self.catalog = ResourceCatalog(root)
        self.profiles = dict(TECH_PROFILES)
        self._load_yaml_profiles()

    def _load_yaml_profiles(self) -> None:
        pdir = self.root / "payload_intelligence" / "profiles"
        if not pdir.exists():
            return
        for f in pdir.glob("*.yaml"):
            try:
                data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
                tech = (data.get("tech") or f.stem).lower()
                self.profiles[tech] = {
                    "nuclei_tags": data.get("nuclei_tags", []),
                    "sensitive": data.get("sensitive_files", data.get("sensitive", [])),
                    "strategy": data.get("strategy", "classic"),
                }
            except Exception as exc:  # noqa: BLE001
                self.logger.debug("profile load failed %s: %s", f, exc)

    def select(self, tech_names: list[str], purpose: str = "discovery") -> Selection:
        tags: list[str] = []
        sensitive: list[str] = list(BASELINE_SENSITIVE)
        strategy = "classic"
        matched: list[str] = []
        for name in tech_names:
            key = name.lower()
            prof = None
            for pk, pv in self.profiles.items():
                if pk in key or key in pk:
                    prof = pv
                    matched.append(pk)
                    break
            if prof:
                tags.extend(prof.get("nuclei_tags", []))
                for s in prof.get("sensitive", []):
                    if s not in sensitive:
                        sensitive.append(s)
                if prof.get("strategy") == "spa":
                    strategy = "spa"
        rationale = (
            f"Matched profiles: {', '.join(sorted(set(matched))) or 'none (baseline)'}"
        )
        return Selection(
            nuclei_tags=sorted(set(tags)),
            sensitive_paths=sensitive,
            wordlist=self.catalog.find_wordlist(*matched, "common"),
            strategy=strategy,
            rationale=rationale,
        )
