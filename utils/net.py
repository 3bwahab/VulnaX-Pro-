"""URL / host normalization and dedup helpers."""
from __future__ import annotations

from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode


def host_of(url_or_host: str) -> str:
    s = url_or_host.strip().lower()
    if "://" in s:
        s = urlparse(s).netloc
    return s.split("/")[0].split(":")[0]


def normalize_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


def normalize_url(url: str) -> str:
    try:
        p = urlparse(url.strip())
    except Exception:
        return url.strip()
    scheme = (p.scheme or "http").lower()
    netloc = p.netloc.lower()
    # drop default ports
    if netloc.endswith(":80") and scheme == "http":
        netloc = netloc[:-3]
    if netloc.endswith(":443") and scheme == "https":
        netloc = netloc[:-4]
    path = p.path or "/"
    query = urlencode(sorted(parse_qsl(p.query)))
    return urlunparse((scheme, netloc, path, "", query, ""))


def url_signature(url: str) -> str:
    """Dedup key: path + sorted param keys (ignores values)."""
    try:
        p = urlparse(url)
    except Exception:
        return url
    keys = sorted(k for k, _ in parse_qsl(p.query))
    return f"{p.netloc.lower()}{p.path}?{'&'.join(keys)}"


def same_registrable(host: str, root: str) -> bool:
    host = normalize_host(host)
    root = normalize_host(root)
    return host == root or host.endswith("." + root)
