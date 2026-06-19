"""Shared async HTTP client used by pure-Python engine baselines."""
from __future__ import annotations

from dataclasses import dataclass, field

import httpx


@dataclass
class HttpResponse:
    url: str
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    text: str = ""
    final_url: str = ""
    elapsed: float = 0.0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


class HttpClient:
    def __init__(self, ctx, max_bytes: int = 600_000):
        self.ctx = ctx
        self.ua = ctx.config.get("user_agent", "VulnaX-Pro/1.0")
        self.timeout = ctx.config.get("timeouts.http", 12.0)
        self.max_bytes = max_bytes
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "HttpClient":
        self._client = httpx.AsyncClient(
            headers={"User-Agent": self.ua},
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        )
        return self

    async def __aexit__(self, *exc) -> None:
        if self._client:
            await self._client.aclose()

    async def fetch(self, url: str, method: str = "GET",
                    host: str | None = None) -> HttpResponse:
        from utils.net import host_of

        target_host = host or host_of(url)
        if not self.ctx.in_scope(url):
            return HttpResponse(url=url, status=0, error="out_of_scope")
        await self.ctx.ratelimiter.acquire(target_host)
        assert self._client is not None
        try:
            resp = await self._client.request(method, url)
            body = resp.text[: self.max_bytes] if resp.text else ""
            return HttpResponse(
                url=url,
                status=resp.status_code,
                headers={k.lower(): v for k, v in resp.headers.items()},
                text=body,
                final_url=str(resp.url),
                elapsed=resp.elapsed.total_seconds(),
            )
        except Exception as exc:  # noqa: BLE001
            return HttpResponse(url=url, status=0, error=type(exc).__name__)
