"""TechnologyDetectionEngine (Stage 2): identify tech/framework/CMS/server.

Triggers Payload Intelligence selection downstream.
"""
from __future__ import annotations

import re

from core.models import Asset, Evidence, Technology
from utils.http import HttpClient

from .base import Engine

# name -> (category, [ (signal_type, regex) ])  signal_type in {header,body,cookie}
FINGERPRINTS: dict[str, tuple[str, list[tuple[str, str]]]] = {
    "WordPress": ("cms", [("body", r"/wp-content/"), ("body", r"wp-includes"),
                          ("header", r"wp-")]),
    "Joomla": ("cms", [("body", r"/media/jui/"), ("body", r"Joomla!")]),
    "Drupal": ("cms", [("header", r"Drupal"), ("body", r"sites/all/"),
                       ("header", r"X-Generator: Drupal")]),
    "Laravel": ("framework", [("cookie", r"laravel_session"),
                              ("cookie", r"XSRF-TOKEN")]),
    "Django": ("framework", [("cookie", r"csrftoken"), ("cookie", r"sessionid"),
                             ("body", r"__admin__")]),
    "Ruby on Rails": ("framework", [("cookie", r"_rails"), ("header", r"X-Powered-By: Phusion")]),
    "Express": ("framework", [("header", r"X-Powered-By: Express")]),
    "Spring": ("framework", [("body", r"Whitelabel Error Page"),
                             ("header", r"X-Application-Context")]),
    "ASP.NET": ("framework", [("header", r"X-AspNet-Version"),
                              ("cookie", r"ASP.NET_SessionId")]),
    "React": ("js-framework", [("body", r"id=\"root\""), ("body", r"react"),
                               ("body", r"__REACT")]),
    "Vue.js": ("js-framework", [("body", r"id=\"app\""), ("body", r"vue(?:\.min)?\.js")]),
    "Angular": ("js-framework", [("body", r"ng-version"), ("body", r"angular")]),
    "Next.js": ("js-framework", [("body", r"/_next/"), ("body", r"__NEXT_DATA__")]),
    "Nginx": ("server", [("header", r"Server: nginx")]),
    "Apache": ("server", [("header", r"Server: Apache")]),
    "IIS": ("server", [("header", r"Server: Microsoft-IIS")]),
    "PHP": ("language", [("header", r"X-Powered-By: PHP"), ("cookie", r"PHPSESSID")]),
    "Cloudflare": ("cdn", [("header", r"Server: cloudflare"), ("header", r"CF-RAY")]),
    "GraphQL": ("api", [("body", r"__schema"), ("body", r"graphql")]),
}

_VERSION_RES = [
    re.compile(r'content="WordPress (\d+\.\d+(?:\.\d+)?)"', re.I),
    re.compile(r"Server: nginx/(\d+\.\d+(?:\.\d+)?)", re.I),
    re.compile(r"Server: Apache/(\d+\.\d+(?:\.\d+)?)", re.I),
    re.compile(r"X-AspNet-Version: (\d+\.\d+(?:\.\d+)?)", re.I),
    re.compile(r"PHP/(\d+\.\d+(?:\.\d+)?)", re.I),
]


class TechnologyDetectionEngine(Engine):
    name = "technology_detection"
    stage = 2
    depends_on = ("asset_validation",)

    async def run(self, ctx) -> None:
        live = ctx.store.assets(status="live")
        async with HttpClient(ctx) as http:
            async def detect(asset: Asset) -> None:
                for scheme in ("https", "http"):
                    resp = await http.fetch(f"{scheme}://{asset.host}", host=asset.host)
                    if resp.ok and resp.status:
                        self._analyze(ctx, asset, resp)
                        break

            await ctx.scheduler.map("http", detect, live)

        n = ctx.store.count(Technology)
        ctx.bus._counters["technologies"] = n
        ctx.bus.emit("counter", counter="technologies", value=n)
        ctx.logger.info("Technology detection: %d technologies", n)

    def _analyze(self, ctx, asset: Asset, resp) -> None:
        header_blob = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        cookie_blob = resp.headers.get("set-cookie", "")
        body = resp.text or ""
        haystacks = {"header": header_blob, "cookie": cookie_blob, "body": body}

        for name, (category, signals) in FINGERPRINTS.items():
            hits = []
            for sigtype, pattern in signals:
                if re.search(pattern, haystacks.get(sigtype, ""), re.I):
                    hits.append((sigtype, pattern))
            if hits:
                version = self._infer_version(header_blob + "\n" + body)
                conf = min(0.5 + 0.2 * len(hits), 0.97)
                ctx.store.add(Technology(
                    asset_id=asset.id, name=name, category=category,
                    version=version, confidence=conf,
                    cpe=_cpe(name, version),
                    evidence=[Evidence(
                        kind="header" if hits[0][0] != "body" else "http_response",
                        summary=f"{name} signal matched: {hits[0][1]}",
                        data={"signals": [h[1] for h in hits]},
                        source=ctx.source("tech"), weight=conf)]))

    def _infer_version(self, blob: str) -> str | None:
        for rx in _VERSION_RES:
            m = rx.search(blob)
            if m:
                return m.group(1)
        return None


def _cpe(name: str, version: str | None) -> str | None:
    slug = name.lower().replace(" ", "_").replace(".", "")
    if version:
        return f"cpe:2.3:a:*:{slug}:{version}:*:*:*:*:*:*:*"
    return None
