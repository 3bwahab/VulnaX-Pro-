"""AssetDiscoveryEngine (Stage 0): maximize candidate assets."""
from __future__ import annotations

import asyncio

from core.models import Asset, Relationship
from integrations.base import Capability, ToolRequest
from utils.net import normalize_host

from .base import Engine

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "api", "dev", "staging", "test", "admin", "portal",
    "app", "blog", "shop", "store", "cdn", "static", "assets", "img", "media",
    "vpn", "remote", "git", "gitlab", "jenkins", "jira", "confluence", "wiki",
    "docs", "support", "help", "status", "monitor", "grafana", "kibana",
    "dashboard", "auth", "login", "sso", "oauth", "secure", "internal", "intranet",
    "beta", "demo", "qa", "uat", "prod", "db", "mysql", "postgres", "redis",
    "smtp", "imap", "pop", "ns1", "ns2", "mx", "webmail", "m", "mobile",
    "graphql", "ws", "socket", "payment", "billing", "account", "user", "files",
]


class AssetDiscoveryEngine(Engine):
    name = "asset_discovery"
    stage = 0

    async def run(self, ctx) -> None:
        roots = ctx.scope.roots
        ctx.logger.info("Discovery roots: %s", roots)
        found: set[str] = set()

        for root in roots:
            found.add(normalize_host(root))
            ctx.store.add(Asset(host=root, type="domain", status="candidate",
                                sources=[ctx.source("scope")]))

        # Passive: certificate transparency (crt.sh) — pure HTTP, in-scope only.
        if ctx.config.get("discovery.ct_logs", True):
            for root in roots:
                for host in await self._crtsh(ctx, root):
                    found.add(host)

        # External subdomain tools (optional accelerators).
        for adapter in ctx.adapters.available(Capability.SUBDOMAIN_ENUM):
            try:
                res = await adapter.run(ToolRequest(targets=roots, timeout_s=120))
                for m in res.models:
                    if isinstance(m, Asset) and ctx.in_scope(m.host):
                        found.add(normalize_host(m.host))
                        ctx.store.add(m)
            except Exception as exc:  # noqa: BLE001
                ctx.logger.debug("adapter %s failed: %s", adapter.name, exc)

        # Active: bounded DNS brute force (pure Python).
        if ctx.config.get("discovery.dns_brute", True):
            limit = ctx.config.get("discovery.max_brute", 200)
            words = COMMON_SUBDOMAINS[:limit]
            for root in roots:
                candidates = [f"{w}.{root}" for w in words]
                resolved = await ctx.scheduler.map(
                    "dns", lambda h: self._resolve(ctx, h), candidates
                )
                for host in resolved:
                    if host:
                        found.add(host)

        # Persist + relationships.
        for host in found:
            host = normalize_host(host)
            if not ctx.in_scope(host):
                continue
            atype = "subdomain" if host not in roots else "domain"
            ctx.store.add(Asset(host=host, type=atype, status="candidate",
                                sources=[ctx.source("discovery")]))
            for root in roots:
                if host != root and host.endswith("." + root):
                    ctx.store.add(Relationship(
                        src_id=Asset(host=root).id, src_type="asset",
                        dst_id=Asset(host=host).id, dst_type="asset",
                        kind="has_subdomain"))

        ctx.bus._counters["assets_found"] = len(found)  # authoritative count
        ctx.bus.emit("counter", counter="assets_found", value=len(found))
        ctx.logger.info("Discovery complete: %d candidate assets", len(found))

    async def _crtsh(self, ctx, root: str) -> set[str]:
        from utils.http import HttpClient

        hosts: set[str] = set()
        url = f"https://crt.sh/?q=%25.{root}&output=json"
        try:
            async with HttpClient(ctx) as http:
                # crt.sh is out of the user's scope, fetch directly (intel source).
                import httpx

                async with httpx.AsyncClient(timeout=20, verify=False) as c:
                    r = await c.get(url, headers={"User-Agent": http.ua})
                    if r.status_code == 200:
                        for row in r.json():
                            for name in str(row.get("name_value", "")).splitlines():
                                name = normalize_host(name.replace("*.", ""))
                                if name.endswith(root) and ctx.in_scope(name):
                                    hosts.add(name)
        except Exception as exc:  # noqa: BLE001
            ctx.logger.debug("crt.sh failed for %s: %s", root, exc)
        return hosts

    async def _resolve(self, ctx, host: str) -> str | None:
        ok = await _resolves(host, ctx.config.get("timeouts.dns", 5.0))
        return host if ok else None


async def _resolves(host: str, timeout: float) -> bool:
    def _q() -> bool:
        try:
            import dns.resolver

            res = dns.resolver.Resolver()
            res.lifetime = timeout
            res.timeout = timeout
            res.resolve(host, "A")
            return True
        except Exception:
            return False

    return await asyncio.to_thread(_q)
