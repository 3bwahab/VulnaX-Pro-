# 11 — Plugin Architecture

## 1. Goal

Let third parties (and future you) extend VulnaX-Pro **without editing core**:
new tools, engines, report templates, tech profiles, and path rules — all drop-in.

## 2. Extension Points

| Point | Base class / location | Discovery |
|-------|----------------------|-----------|
| Tool adapter | `integrations.base.ToolAdapter` | entry-point + `plugins/` scan |
| Engine | `engines.base.Engine` | registered with pipeline by name |
| Report renderer | `engines.reporting.Renderer` | template auto-discovery |
| Tech profile | yaml in `payload_intelligence/profiles/` | catalog scan |
| Path rule pack | yaml path rules | loaded by AttackPathEngine |
| Correlation/Config rule pack | yaml | loaded by respective engine |
| LLM provider | `integrations.llm.base.LLMAdapter` | registry |

## 3. Discovery Mechanism

Two complementary methods:
1. **Python entry points** (`pyproject.toml`):
   ```toml
   [project.entry-points."vulnax.adapters"]
   shodan = "vulnax_shodan.adapter:ShodanAdapter"
   [project.entry-points."vulnax.engines"]
   secrets_scan = "vulnax_secrets.engine:SecretsEngine"
   ```
2. **`plugins/` folder scan** — local, uninstalled plugins for quick dev. Each
   subfolder with a `plugin.py` exposing `register(registry)` is loaded at startup.

## 4. Plugin Manifest

Each plugin declares a manifest (`plugin.toml`):
```toml
[plugin]
name = "shodan-intel"
version = "0.1.0"
kind = "adapter"               # adapter|engine|renderer|profile|rules
provides = ["SUBDOMAIN_ENUM"]  # capabilities (for adapters)
requires = ["VULNAX_SHODAN_API_KEY"]
api_version = "1.x"            # framework plugin API compatibility
```

The loader enforces `api_version` compatibility and reports incompatible plugins
instead of crashing.

## 5. Engine Plugin Contract

A plugin engine is a normal `Engine` subclass: it declares `stage`, `depends_on`,
`requires_tools`, and `run()`. The pipeline inserts it by topological order. It
reads/writes only `core/models.py` types via the store — same contract as built-ins,
so it composes with correlation, graph, risk, and reporting automatically.

## 6. Adapter Plugin Contract

A plugin adapter subclasses `ToolAdapter`, declares capabilities and `produces`,
and implements `normalize()`. The registry exposes it by capability, so existing
engines can use it with no changes (e.g., a new SUBDOMAIN_ENUM source is unioned
into discovery automatically).

## 7. Safety & Isolation

- Plugins run **in-process** (single-process design) — so they are trusted code.
- Manifest `requires` (env keys) validated before load; missing → plugin disabled
  with a warning, never a crash.
- Plugin exceptions are isolated like engine errors: degrade, don't crash.
- A `--no-plugins` flag and an allowlist in config gate what loads (supply-chain
  caution).

## 8. Versioned Plugin API

The framework exposes a stable `vulnax.api` surface (models, base classes, registry,
context). Semantic versioning; plugins declare the range they support. Internal
core modules are **not** part of the plugin API and may change freely.

## 9. Example: Minimal Plugin Engine

```python
# plugins/takeover/plugin.py
from vulnax.api import Engine, Finding, Severity, Confidence, Evidence

class SubdomainTakeoverEngine(Engine):
    name = "subdomain_takeover"
    stage = 5
    depends_on = ("asset_validation", "technology_detection")

    async def run(self, ctx):
        for asset in ctx.store.assets(status="live"):
            if self._dangling_cname(asset):
                ctx.store.add(Finding(
                    title="Potential subdomain takeover",
                    category="exposure", asset_id=asset.id, target=asset.host,
                    severity=Severity.HIGH,
                    confidence=Confidence(score=0.8, rationale="dangling CNAME",
                                          signals=2),
                    evidence=[Evidence(kind="config",
                              summary=f"CNAME -> {asset.cname} unclaimed", data={}, weight=0.8,
                              source=ctx.source("takeover"))],
                    impact="Attacker may claim the service and serve content.",
                    remediation="Remove or reclaim the dangling DNS record.",
                ))

def register(registry):
    registry.add_engine(SubdomainTakeoverEngine)
```
