"""Concrete tool adapters. All optional — engines have pure-Python baselines.

Each adapter normalizes native (JSONL) output into typed models. If the binary
is absent, the adapter reports unavailable and the engine degrades gracefully.
"""
from __future__ import annotations

import json
from pathlib import Path

from core.models import Asset, Endpoint, Finding, Service, Severity, Technology, \
    Confidence, Evidence, ToolSource

from .base import AdapterResult, Capability, ToolAdapter, ToolRequest
from .process import run_process

_ROOT = Path(__file__).resolve().parent.parent
SUBFINDER_PROVIDER_CONFIG = _ROOT / "config" / "subfinder-provider-config.yaml"


def _jsonl(raw: str):
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except Exception:
            continue


class SubfinderAdapter(ToolAdapter):
    name = "subfinder"
    binary = "subfinder"
    capabilities = {Capability.SUBDOMAIN_ENUM}

    async def run(self, request: ToolRequest) -> AdapterResult:
        if not self.is_available():
            return AdapterResult(errors=["unavailable"])
        models: list = []
        src = ToolSource(name=self.name)
        pc: list[str] = []
        if SUBFINDER_PROVIDER_CONFIG.exists():
            pc = ["-pc", str(SUBFINDER_PROVIDER_CONFIG), "-all"]
        for domain in request.targets:
            res = await run_process(
                [self.binary, "-silent", "-d", domain, *pc],
                timeout=request.timeout_s,
            )
            for host in res.stdout.splitlines():
                host = host.strip().lower()
                if host:
                    models.append(Asset(host=host, type="subdomain", sources=[src]))
        return AdapterResult(models=models)


class HttpxAdapter(ToolAdapter):
    name = "httpx"
    binary = "httpx"
    capabilities = {Capability.HTTP_PROBE}

    async def run(self, request: ToolRequest) -> AdapterResult:
        if not self.is_available():
            return AdapterResult(errors=["unavailable"])
        src = ToolSource(name=self.name)
        stdin = "\n".join(request.targets)
        res = await run_process(
            [self.binary, "-silent", "-json", "-title", "-tech-detect",
             "-status-code"],
            stdin_data=stdin, timeout=request.timeout_s,
        )
        models: list = []
        for obj in _jsonl(res.stdout):
            host = (obj.get("host") or obj.get("input") or "").lower()
            if not host:
                continue
            models.append(Asset(host=host, status="live",
                                ips=obj.get("a", []) or [], sources=[src]))
            models.append(Endpoint(
                asset_id="", url=obj.get("url", ""),
                status_code=obj.get("status_code"),
                title=obj.get("title"), source="probe", sources=[src]))
            for tech in obj.get("tech", []) or []:
                models.append(Technology(asset_id="", name=tech, confidence=0.6))
        return AdapterResult(models=models)


class NaabuAdapter(ToolAdapter):
    name = "naabu"
    binary = "naabu"
    capabilities = {Capability.PORT_SCAN}

    async def run(self, request: ToolRequest) -> AdapterResult:
        if not self.is_available():
            return AdapterResult(errors=["unavailable"])
        src = ToolSource(name=self.name)
        stdin = "\n".join(request.targets)
        # Connect scan (-s c): portable, needs no npcap/root on Windows.
        res = await run_process(
            [self.binary, "-silent", "-json", "-s", "c"], stdin_data=stdin,
            timeout=request.timeout_s,
        )
        models: list = []
        for obj in _jsonl(res.stdout):
            host = (obj.get("host") or obj.get("ip") or "").lower()
            port = obj.get("port")
            if host and port:
                models.append(Service(asset_id="", host=host, port=int(port),
                                      sources=[src]))
        return AdapterResult(models=models)


class KatanaAdapter(ToolAdapter):
    name = "katana"
    binary = "katana"
    capabilities = {Capability.CRAWL}

    async def run(self, request: ToolRequest) -> AdapterResult:
        if not self.is_available():
            return AdapterResult(errors=["unavailable"])
        src = ToolSource(name=self.name)
        stdin = "\n".join(request.targets)
        depth = str(request.options.get("depth", 2))
        res = await run_process(
            [self.binary, "-silent", "-jc", "-d", depth],
            stdin_data=stdin, timeout=request.timeout_s,
        )
        models: list = []
        for line in res.stdout.splitlines():
            url = line.strip()
            if url.startswith("http"):
                models.append(Endpoint(asset_id="", url=url, source="crawl",
                                       is_js=url.endswith(".js"), sources=[src]))
        return AdapterResult(models=models)


class NucleiAdapter(ToolAdapter):
    name = "nuclei"
    binary = "nuclei"
    capabilities = {Capability.TEMPLATE_SCAN}

    async def run(self, request: ToolRequest) -> AdapterResult:
        if not self.is_available():
            return AdapterResult(errors=["unavailable"])
        src = ToolSource(name=self.name)
        stdin = "\n".join(request.targets)
        cmd = [self.binary, "-silent", "-jsonl"]
        tags = request.options.get("tags")
        if tags:
            cmd += ["-tags", ",".join(tags)]
        res = await run_process(cmd, stdin_data=stdin, timeout=request.timeout_s)
        sev_map = {
            "critical": Severity.CRITICAL, "high": Severity.HIGH,
            "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
        }
        models: list = []
        for obj in _jsonl(res.stdout):
            info = obj.get("info", {})
            sev = sev_map.get((info.get("severity") or "info").lower(), Severity.INFO)
            models.append(Finding(
                title=info.get("name", obj.get("template-id", "nuclei finding")),
                category="vuln", target=obj.get("matched-at", obj.get("host", "")),
                severity=sev,
                confidence=Confidence(score=0.85, rationale="nuclei template match",
                                      signals=1),
                evidence=[Evidence(kind="behavioral",
                                   summary=f"Nuclei: {obj.get('template-id')}",
                                   data={"matched": obj.get("matched-at")},
                                   source=src, weight=0.85)],
                impact=info.get("description", ""),
                remediation=info.get("remediation", "See template references."),
                references=info.get("reference", []) or [],
                detected_by=["nuclei"],
            ))
        return AdapterResult(models=models)


class DalfoxAdapter(ToolAdapter):
    """Reflected/DOM XSS validation (active; gated by --active)."""
    name = "dalfox"
    binary = "dalfox"
    capabilities = {Capability.XSS_SCAN}
    version_args = ["version"]

    async def run(self, request: ToolRequest) -> AdapterResult:
        if not self.is_available():
            return AdapterResult(errors=["unavailable"])
        src = ToolSource(name=self.name)
        stdin = "\n".join(request.targets)
        res = await run_process(
            [self.binary, "pipe", "--format", "json", "--no-spinner"],
            stdin_data=stdin, timeout=request.timeout_s)
        models: list = []
        for obj in _jsonl(res.stdout):
            models.append(Finding(
                title=f"Reflected XSS ({obj.get('type','xss')})", category="vuln",
                target=obj.get("data", obj.get("url", "")), severity=Severity.HIGH,
                confidence=Confidence(score=0.9, rationale="dalfox PoC", signals=1),
                evidence=[Evidence(kind="behavioral",
                          summary=f"dalfox: {obj.get('evidence','')[:120]}",
                          data={"param": obj.get("param"), "poc": obj.get("data")},
                          source=src, weight=0.9)],
                impact="Cross-site scripting allows session/credential theft.",
                remediation="Context-encode output; apply CSP.", cwe="CWE-79",
                detected_by=["dalfox"]))
        return AdapterResult(models=models)


class SQLMapAdapter(ToolAdapter):
    """SQL injection validation (active; gated by --active)."""
    name = "sqlmap"
    binary = "sqlmap"
    capabilities = {Capability.SQLI_SCAN}
    version_args = ["--version"]

    async def run(self, request: ToolRequest) -> AdapterResult:
        if not self.is_available():
            return AdapterResult(errors=["unavailable"])
        src = ToolSource(name=self.name)
        models: list = []
        for url in request.targets[:20]:  # bounded: SQLMap is heavy
            res = await run_process(
                [self.binary, "-u", url, "--batch", "--level", "1", "--risk", "1",
                 "--smart", "--disable-coloring"], timeout=request.timeout_s)
            if "is vulnerable" in res.stdout or "sqlmap identified" in res.stdout:
                models.append(Finding(
                    title="SQL injection confirmed", category="vuln", target=url,
                    severity=Severity.CRITICAL,
                    confidence=Confidence(score=0.95, rationale="sqlmap confirmed",
                                          signals=1),
                    evidence=[Evidence(kind="behavioral",
                              summary="sqlmap confirmed injectable parameter",
                              data={"url": url}, source=src, weight=0.95)],
                    impact="Database compromise / data exfiltration.",
                    remediation="Use parameterized queries / ORM bindings.",
                    cwe="CWE-89", detected_by=["sqlmap"]))
        return AdapterResult(models=models)


class FeroxbusterAdapter(ToolAdapter):
    name = "feroxbuster"
    binary = "feroxbuster"
    capabilities = {Capability.CONTENT_DISCOVERY}
    version_args = ["--version"]

    async def run(self, request: ToolRequest) -> AdapterResult:
        if not self.is_available():
            return AdapterResult(errors=["unavailable"])
        src = ToolSource(name=self.name)
        models: list = []
        wordlist = request.options.get("wordlist")
        for url in request.targets:
            cmd = [self.binary, "-u", url, "--silent", "--json"]
            if wordlist:
                cmd += ["-w", str(wordlist)]
            res = await run_process(cmd, timeout=request.timeout_s)
            for obj in _jsonl(res.stdout):
                if obj.get("type") == "response" and obj.get("url"):
                    models.append(Endpoint(asset_id="", url=obj["url"],
                                  status_code=obj.get("status"),
                                  source="content_discovery", sources=[src]))
        return AdapterResult(models=models)


class DirsearchAdapter(ToolAdapter):
    name = "dirsearch"
    binary = "dirsearch"
    capabilities = {Capability.CONTENT_DISCOVERY}
    version_args = ["--version"]

    async def run(self, request: ToolRequest) -> AdapterResult:
        if not self.is_available():
            return AdapterResult(errors=["unavailable"])
        src = ToolSource(name=self.name)
        models: list = []
        for url in request.targets:
            res = await run_process(
                [self.binary, "-u", url, "--format=plain", "-q"],
                timeout=request.timeout_s)
            for line in res.stdout.splitlines():
                line = line.strip()
                if line.startswith("http"):
                    models.append(Endpoint(asset_id="", url=line.split()[-1],
                                  source="content_discovery", sources=[src]))
        return AdapterResult(models=models)


class GowitnessAdapter(ToolAdapter):
    """Headless screenshot capture (optional). Degrades to classification-only."""
    name = "gowitness"
    binary = "gowitness"
    capabilities = {Capability.SCREENSHOT}
    version_args = ["version"]

    async def run(self, request: ToolRequest) -> AdapterResult:
        if not self.is_available():
            return AdapterResult(errors=["unavailable"])
        outdir = request.options.get("outdir", ".")
        captured: dict[str, str] = {}
        for url in request.targets:
            res = await run_process(
                [self.binary, "single", "--screenshot-path", str(outdir), url],
                timeout=request.timeout_s)
            # gowitness names files after the URL; record best-effort.
            if res.returncode == 0:
                captured[url] = str(outdir)
        return AdapterResult(raw=str(captured))


ALL_ADAPTERS = [
    SubfinderAdapter, HttpxAdapter, NaabuAdapter, KatanaAdapter, NucleiAdapter,
    DalfoxAdapter, SQLMapAdapter, FeroxbusterAdapter, DirsearchAdapter,
    GowitnessAdapter,
]
