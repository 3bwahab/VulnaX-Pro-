"""AssetValidationEngine (Stage 1): resolve + probe to find live assets."""
from __future__ import annotations

import asyncio
import re

from core.models import Asset, Endpoint, TlsInfo
from utils.http import HttpClient

from .base import Engine

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


class AssetValidationEngine(Engine):
    name = "asset_validation"
    stage = 1
    depends_on = ("asset_discovery",)

    async def run(self, ctx) -> None:
        candidates = ctx.store.assets(status="candidate")
        live = 0
        async with HttpClient(ctx) as http:
            async def probe(asset: Asset) -> bool:
                ips = await _resolve_ips(asset.host, ctx.config.get("timeouts.dns", 5.0))
                if not ips:
                    ctx.store.add(Asset(host=asset.host, status="dead"))
                    return False
                hit = False
                for scheme in ("https", "http"):
                    url = f"{scheme}://{asset.host}"
                    resp = await http.fetch(url, host=asset.host)
                    if resp.ok and resp.status:
                        hit = True
                        title = _extract_title(resp.text)
                        tls = TlsInfo(enabled=scheme == "https")
                        cdn = _detect_cdn(resp.headers)
                        ctx.store.add(Asset(
                            host=asset.host, status="live", ips=ips,
                            tls=tls, cdn=cdn,
                            sources=[ctx.source("validation")]))
                        ep = Endpoint(
                            asset_id=Asset(host=asset.host).id,
                            url=resp.final_url or url, status_code=resp.status,
                            content_type=resp.headers.get("content-type"),
                            title=title, source="probe",
                            sources=[ctx.source("validation")])
                        ctx.store.add(ep)
                        ctx.bus.incr("urls")
                        break
                if not hit:
                    ctx.store.add(Asset(host=asset.host, status="dead", ips=ips))
                return hit

            results = await ctx.scheduler.map("http", probe, candidates)
            live = sum(1 for r in results if r)

        ctx.bus._counters["live_assets"] = live
        ctx.bus.emit("counter", counter="live_assets", value=live)
        ctx.logger.info("Validation: %d live of %d candidates", live, len(candidates))


def _extract_title(html: str) -> str | None:
    m = _TITLE_RE.search(html or "")
    return m.group(1).strip()[:200] if m else None


def _detect_cdn(headers: dict[str, str]) -> str | None:
    server = headers.get("server", "").lower()
    if "cloudflare" in server or "cf-ray" in headers:
        return "cloudflare"
    if "akamai" in server:
        return "akamai"
    if "fastly" in server or "x-served-by" in headers:
        return "fastly"
    if "amazons3" in server or "x-amz-cf-id" in headers:
        return "aws"
    return None


async def _resolve_ips(host: str, timeout: float) -> list[str]:
    def _q() -> list[str]:
        out: list[str] = []
        try:
            import dns.resolver

            res = dns.resolver.Resolver()
            res.lifetime = timeout
            res.timeout = timeout
            for rtype in ("A", "AAAA"):
                try:
                    for r in res.resolve(host, rtype):
                        out.append(str(r))
                except Exception:
                    continue
        except Exception:
            pass
        return out

    return await asyncio.to_thread(_q)
