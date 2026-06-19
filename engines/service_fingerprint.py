"""ServiceFingerprintEngine (Stage 2): port + service discovery."""
from __future__ import annotations

import asyncio

from core.models import Service
from integrations.base import Capability, ToolRequest

from .base import Engine

_PORT_SERVICE = {
    21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
    143: "imap", 443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
    1433: "mssql", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8000: "http-alt", 8080: "http-proxy",
    8443: "https-alt", 8888: "http-alt", 9200: "elasticsearch", 27017: "mongodb",
}


class ServiceFingerprintEngine(Engine):
    name = "service_fingerprint"
    stage = 2
    depends_on = ("asset_validation",)

    async def run(self, ctx) -> None:
        live = ctx.store.assets(status="live")
        ports = ctx.config.get("ports.top", [80, 443, 8080, 8443])
        # Respect scope port restriction if narrower.
        if ctx.scope.ports:
            ports = [p for p in ports if p in ctx.scope.ports] or ctx.scope.ports

        count = 0
        # Optional accelerator: naabu.
        naabu = next(iter(ctx.adapters.available(Capability.PORT_SCAN)), None)
        if naabu:
            try:
                res = await naabu.run(ToolRequest(
                    targets=[a.host for a in live], timeout_s=180))
                for m in res.models:
                    if isinstance(m, Service):
                        m.asset_id = m.asset_id or _aid(m.host)
                        m.service = _PORT_SERVICE.get(m.port)
                        ctx.store.add(m)
                        count += 1
            except Exception as exc:  # noqa: BLE001
                ctx.logger.debug("naabu failed: %s", exc)

        if count == 0:
            # Pure-Python async TCP connect scan.
            async def scan(asset) -> int:
                local = 0
                for port in ports:
                    if await _tcp_open(asset.host, port,
                                       ctx.config.get("timeouts.dns", 3.0)):
                        banner = await _grab_banner(asset.host, port)
                        ctx.store.add(Service(
                            asset_id=asset.id, host=asset.host, port=port,
                            service=_PORT_SERVICE.get(port), banner=banner,
                            sources=[ctx.source("portscan")]))
                        local += 1
                return local

            results = await ctx.scheduler.map("dns", scan, live)
            count = sum(results)

        ctx.bus._counters["services"] = ctx.store.count(Service)
        ctx.bus.emit("counter", counter="services", value=ctx.store.count(Service))
        ctx.logger.info("Service discovery: %d services", ctx.store.count(Service))


def _aid(host: str) -> str:
    from core.models import Asset
    return Asset(host=host).id


async def _tcp_open(host: str, port: int, timeout: float) -> bool:
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _grab_banner(host: str, port: int) -> str | None:
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=2.0)
        try:
            data = await asyncio.wait_for(reader.read(120), timeout=1.5)
        except Exception:
            data = b""
        writer.close()
        return data.decode("utf-8", "replace").strip() or None
    except Exception:
        return None
