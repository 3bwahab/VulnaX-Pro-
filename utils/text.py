"""Regex libraries for endpoint / secret / reference extraction."""
from __future__ import annotations

import math
import re

# Endpoint / path extraction from JS and HTML.
ENDPOINT_RE = re.compile(
    r"""['"`]((?:https?:)?/[a-zA-Z0-9_\-./]{2,}(?:\?[^'"`\s]{0,120})?)['"`]"""
)
ABS_URL_RE = re.compile(r"""https?://[a-zA-Z0-9._\-]+(?:/[a-zA-Z0-9_\-./?=&%]*)?""")

# Secret patterns (subset of common high-signal tokens).
SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_key": re.compile(r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "slack_token": re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,48}"),
    "github_token": re.compile(r"gh[pousr]_[0-9A-Za-z]{36}"),
    "stripe_key": re.compile(r"sk_live_[0-9a-zA-Z]{24}"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    "generic_secret": re.compile(
        r"""(?i)(?:api[_-]?key|secret|token|passwd|password)['"`]?\s*[:=]\s*['"`]([0-9a-zA-Z\-_!@#$%^&*]{12,})['"`]"""
    ),
}

CLOUD_RE = re.compile(
    r"(?:[a-z0-9.\-]+\.s3[.\-][a-z0-9.\-]*amazonaws\.com|"
    r"s3://[a-z0-9.\-]+|"
    r"[a-z0-9.\-]+\.blob\.core\.windows\.net|"
    r"storage\.googleapis\.com/[a-z0-9._\-]+|"
    r"[a-z0-9.\-]+\.firebaseio\.com)"
)

GRAPHQL_RE = re.compile(r"(?:/graphql|/graphiql|__schema|IntrospectionQuery)")

ADMIN_RE = re.compile(r"/(?:admin|dashboard|manage|console|internal|debug)(?:/|\b)")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def looks_secret(value: str) -> bool:
    return len(value) >= 16 and shannon_entropy(value) >= 3.5


def extract_endpoints(text: str) -> set[str]:
    out: set[str] = set()
    for m in ENDPOINT_RE.finditer(text):
        path = m.group(1)
        if path and not path.startswith("//") and len(path) <= 200:
            out.add(path)
    for m in ABS_URL_RE.finditer(text):
        out.add(m.group(0))
    return out


def extract_secrets(text: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for kind, rx in SECRET_PATTERNS.items():
        for m in rx.finditer(text):
            val = m.group(1) if m.groups() else m.group(0)
            if kind == "generic_secret" and not looks_secret(val):
                continue
            found.append((kind, val[:80]))
    return found
