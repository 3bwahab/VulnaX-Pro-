"""Concrete LLM providers: Anthropic, OpenAI-compatible (DeepSeek/Kimi/OpenRouter),
and Gemini. Keys come from environment (loaded from .env). All use httpx so no
provider SDK is required.
"""
from __future__ import annotations

import os

import httpx

from .base import LLMProvider

_TIMEOUT = 60.0


def _first_key(env_names: list[str]) -> str | None:
    for name in env_names:
        val = os.environ.get(name)
        if val:
            return val
    return None


def _all_keys(env_names: list[str]) -> list[str]:
    return [os.environ[n] for n in env_names if os.environ.get(n)]


class OpenAICompatProvider(LLMProvider):
    """Works for DeepSeek, Kimi/Moonshot, OpenRouter — OpenAI chat-completions API."""

    def __init__(self, name: str, base_url: str, keys: list[str], model: str):
        self.name = name
        self.base_url = base_url.rstrip("/")
        self.keys = keys
        self.model = model

    @property
    def available(self) -> bool:
        return bool(self.keys)

    async def complete(self, system: str, prompt: str, max_tokens: int = 500) -> str:
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "max_tokens": max_tokens,
            "temperature": 0.2,
        }
        last_err: Exception | None = None
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            for key in self.keys:  # rotate keys on failure
                headers = {"Authorization": f"Bearer {key}",
                           "Content-Type": "application/json"}
                if "openrouter" in self.base_url:
                    headers["HTTP-Referer"] = "https://vulnax-pro.local"
                    headers["X-Title"] = "VulnaX-Pro"
                try:
                    r = await client.post(f"{self.base_url}/chat/completions",
                                          json=body, headers=headers)
                    r.raise_for_status()
                    data = r.json()
                    return data["choices"][0]["message"]["content"] or ""
                except Exception as exc:  # noqa: BLE001
                    last_err = exc
                    continue
        raise RuntimeError(f"{self.name} failed: {last_err}")


class AnthropicProvider(LLMProvider):
    def __init__(self, base_url: str, key: str | None, model: str):
        self.name = "anthropic"
        self.base_url = base_url.rstrip("/")
        self.key = key
        self.model = model

    @property
    def available(self) -> bool:
        return bool(self.key)

    async def complete(self, system: str, prompt: str, max_tokens: int = 500) -> str:
        headers = {"x-api-key": self.key or "", "anthropic-version": "2023-06-01",
                   "Content-Type": "application/json"}
        body = {"model": self.model, "max_tokens": max_tokens, "system": system,
                "messages": [{"role": "user", "content": prompt}]}
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            r = await client.post(f"{self.base_url}/v1/messages",
                                  json=body, headers=headers)
            r.raise_for_status()
            data = r.json()
            return "".join(b.get("text", "") for b in data.get("content", []))


class GeminiProvider(LLMProvider):
    def __init__(self, base_url: str, key: str | None, model: str):
        self.name = "gemini"
        self.base_url = base_url.rstrip("/")
        self.key = key
        self.model = model

    @property
    def available(self) -> bool:
        return bool(self.key)

    async def complete(self, system: str, prompt: str, max_tokens: int = 500) -> str:
        url = f"{self.base_url}/models/{self.model}:generateContent"
        body = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"maxOutputTokens": max_tokens, "temperature": 0.2},
        }
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            # API-key auth (query param) with Bearer fallback for OAuth-style tokens.
            try:
                r = await client.post(url, params={"key": self.key}, json=body)
                r.raise_for_status()
            except Exception:
                r = await client.post(
                    url, json=body,
                    headers={"Authorization": f"Bearer {self.key}"})
                r.raise_for_status()
            data = r.json()
            cands = data.get("candidates", [])
            if not cands:
                return ""
            parts = cands[0].get("content", {}).get("parts", [])
            return "".join(p.get("text", "") for p in parts)


class ChainProvider(LLMProvider):
    """Tries each provider in order until one returns text."""

    def __init__(self, providers: list[LLMProvider], logger=None):
        self.providers = [p for p in providers if p.available]
        self.logger = logger
        self.name = "+".join(p.name for p in self.providers) or "none"
        self.model = self.providers[0].model if self.providers else ""

    @property
    def available(self) -> bool:
        return bool(self.providers)

    @property
    def active_name(self) -> str:
        return self.providers[0].name if self.providers else "none"

    async def complete(self, system: str, prompt: str, max_tokens: int = 500) -> str:
        last_err: Exception | None = None
        for p in self.providers:
            try:
                out = await p.complete(system, prompt, max_tokens)
                if out and out.strip():
                    self.model = p.model
                    return out
            except Exception as exc:  # noqa: BLE001
                last_err = exc
                if self.logger:
                    self.logger.debug("LLM provider %s failed: %s", p.name, exc)
                continue
        raise RuntimeError(f"all LLM providers failed: {last_err}")


def _make_provider(name: str, cfg: dict) -> LLMProvider | None:
    kind = cfg.get("kind")
    env = cfg.get("env", [])
    if isinstance(env, str):
        env = [env]
    model = cfg.get("model", "")
    base = cfg.get("base_url", "")
    if kind == "anthropic":
        return AnthropicProvider(base, _first_key(env), model)
    if kind == "gemini":
        return GeminiProvider(base, _first_key(env), model)
    if kind == "openai":
        return OpenAICompatProvider(name, base, _all_keys(env), model)
    return None


def build_llm(config, logger=None) -> ChainProvider:
    """Build the active LLM provider chain from config + present env keys."""
    ai = config.get("ai", {}) or {}
    providers_cfg = ai.get("providers", {}) or {}
    selection = ai.get("provider", "auto")
    priority = ai.get("priority", list(providers_cfg.keys()))

    order = priority if selection == "auto" else [selection]
    built: list[LLMProvider] = []
    for name in order:
        cfg = providers_cfg.get(name)
        if not cfg:
            continue
        p = _make_provider(name, cfg)
        if p and p.available:
            built.append(p)
    return ChainProvider(built, logger)
