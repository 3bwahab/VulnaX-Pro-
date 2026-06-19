"""DeepCrawlerEngine (Stage 3): maximize URL/endpoint coverage."""
from __future__ import annotations

import asyncio
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from core.models import Asset, Endpoint
from utils.http import HttpClient
from utils.net import normalize_url, url_signature

from .base import Engine


class DeepCrawlerEngine(Engine):
    name = "deep_crawler"
    stage = 3
    depends_on = ("technology_detection",)

    async def run(self, ctx) -> None:
        live = ctx.store.assets(status="live")
        max_pages = ctx.config.get("crawler.max_pages", 150)
        max_depth = ctx.config.get("crawler.max_depth", 2)

        async with HttpClient(ctx) as http:
            async def crawl_asset(asset: Asset) -> None:
                await self._crawl(ctx, http, asset, max_pages, max_depth)

            await ctx.scheduler.map("http", crawl_asset, live)

        # Content discovery (sensitive paths from payload intelligence).
        await self._content_discovery(ctx)

        n = ctx.store.count(Endpoint)
        ctx.bus._counters["urls"] = n
        ctx.bus.emit("counter", counter="urls", value=n)
        js = sum(1 for e in ctx.store.endpoints() if e.is_js)
        ctx.logger.info("Crawler: %d endpoints (%d JS)", n, js)

    async def _crawl(self, ctx, http, asset, max_pages, max_depth) -> None:
        base = f"https://{asset.host}"
        seen_sigs: set[str] = set()
        queue: list[tuple[str, int]] = [(base, 0)]
        pages = 0
        while queue and pages < max_pages:
            url, depth = queue.pop(0)
            sig = url_signature(url)
            if sig in seen_sigs:
                continue
            seen_sigs.add(sig)
            resp = await http.fetch(url, host=asset.host)
            if not resp.ok or not resp.status:
                continue
            pages += 1
            ctype = resp.headers.get("content-type", "")
            is_js = url.endswith(".js") or "javascript" in ctype
            ctx.store.add(Endpoint(
                asset_id=asset.id, url=normalize_url(url),
                status_code=resp.status, content_type=ctype,
                source="crawl", is_js=is_js,
                sources=[ctx.source("crawler")]))
            ctx.bus.incr("urls")
            if is_js or "html" not in ctype:
                continue
            for link, is_js_link in self._extract_links(resp.text, url):
                if not ctx.in_scope(link):
                    continue
                if is_js_link:
                    ctx.store.add(Endpoint(
                        asset_id=asset.id, url=normalize_url(link),
                        source="crawl", is_js=True,
                        sources=[ctx.source("crawler")]))
                    ctx.bus.incr("js_files")
                elif depth < max_depth:
                    queue.append((link, depth + 1))
            self._extract_forms(ctx, asset, resp.text, url)

    def _extract_links(self, html: str, base: str) -> list[tuple[str, bool]]:
        out: list[tuple[str, bool]] = []
        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            return out
        host = urlparse(base).netloc
        for tag, attr in (("a", "href"), ("script", "src"), ("link", "href")):
            for el in soup.find_all(tag):
                val = el.get(attr)
                if not val or val.startswith(("#", "mailto:", "javascript:", "tel:")):
                    continue
                full = urljoin(base, val)
                if urlparse(full).netloc != host:
                    continue
                is_js = full.endswith(".js") or (tag == "script" and bool(val))
                out.append((full, is_js))
        return out

    def _extract_forms(self, ctx, asset, html, base) -> None:
        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            return
        for form in soup.find_all("form"):
            action = urljoin(base, form.get("action") or base)
            method = (form.get("method") or "GET").upper()
            params = [i.get("name") for i in form.find_all(["input", "select",
                      "textarea"]) if i.get("name")]
            if ctx.in_scope(action):
                ctx.store.add(Endpoint(
                    asset_id=asset.id, url=normalize_url(action), method=method,
                    params=params, source="form",
                    sources=[ctx.source("crawler")]))

    async def _content_discovery(self, ctx) -> None:
        live = ctx.store.assets(status="live")
        async with HttpClient(ctx) as http:
            async def probe(asset: Asset) -> None:
                techs = [t.name for t in ctx.store.technologies_for(asset.id)]
                selection = ctx.payloads.select(techs, purpose="discovery")
                ctx.logger.debug("payload selection %s: %s", asset.host,
                                 selection.rationale)
                for path in selection.sensitive_paths[:40]:
                    url = f"https://{asset.host}{path}"
                    if not ctx.in_scope(url):
                        continue
                    resp = await http.fetch(url, host=asset.host)
                    if resp.ok and resp.status in (200, 401, 403):
                        ctx.store.add(Endpoint(
                            asset_id=asset.id, url=normalize_url(url),
                            status_code=resp.status,
                            content_type=resp.headers.get("content-type"),
                            source="content_discovery",
                            sources=[ctx.source("content_discovery")]))

            await ctx.scheduler.map("http", probe, live)
