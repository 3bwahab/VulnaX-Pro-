"""Scope guard. Out-of-scope targets are refused at the integration layer."""
from __future__ import annotations

import fnmatch
import ipaddress
from pathlib import Path
from typing import Any

import yaml

from .errors import ScopeError


class Scope:
    def __init__(self, data: dict[str, Any]):
        s = data.get("scope", data)
        inc = s.get("in_scope", {})
        exc = s.get("out_of_scope", {})
        self.domains: list[str] = [d.lower() for d in inc.get("domains", [])]
        self.cidrs: list[str] = inc.get("cidrs", [])
        self.exclude_domains: list[str] = [d.lower() for d in exc.get("domains", [])]
        self.ports: list[int] = s.get("ports", [80, 443, 8080, 8443])
        self.rate: dict[str, Any] = s.get("rate", {})
        self._networks = []
        for c in self.cidrs:
            try:
                self._networks.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                pass

    @property
    def roots(self) -> list[str]:
        """Root domains (strip leading wildcard) used to seed discovery."""
        out = []
        for d in self.domains:
            out.append(d[2:] if d.startswith("*.") else d)
        return sorted(set(out))

    def _is_ip(self, host: str) -> bool:
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def is_in_scope(self, target: str) -> bool:
        host = target.lower().strip()
        # strip scheme/path/port if a URL was passed
        if "://" in host:
            host = host.split("://", 1)[1]
        host = host.split("/")[0].split(":")[0]
        if not host:
            return False

        for ex in self.exclude_domains:
            if host == ex or fnmatch.fnmatch(host, ex):
                return False

        if self._is_ip(host):
            ip = ipaddress.ip_address(host)
            return any(ip in net for net in self._networks)

        for d in self.domains:
            if d.startswith("*."):
                base = d[2:]
                if host == base or host.endswith("." + base):
                    return True
            elif host == d or host.endswith("." + d):
                return True
        return False


def load_scope(path: str | None = None, domain: str | None = None) -> Scope:
    if domain:
        return Scope(
            {
                "scope": {
                    "in_scope": {"domains": [domain, f"*.{domain}"]},
                    "ports": [80, 443, 8080, 8443, 8000, 8888],
                }
            }
        )
    if not path:
        raise ScopeError("A scope file (--scope) or a domain (-d) is required.")
    p = Path(path)
    if not p.exists():
        raise ScopeError(f"Scope file not found: {path}")
    with open(p, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    scope = Scope(data)
    if not scope.domains and not scope.cidrs:
        raise ScopeError("Scope defines no in-scope domains or CIDRs.")
    return scope
