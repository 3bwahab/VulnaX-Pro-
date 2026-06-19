"""LLM provider contract. Consumes structured prompts, returns text."""
from __future__ import annotations

from abc import ABC, abstractmethod


class LLMProvider(ABC):
    name: str = "llm"
    model: str = ""

    @property
    @abstractmethod
    def available(self) -> bool: ...

    @abstractmethod
    async def complete(self, system: str, prompt: str,
                       max_tokens: int = 500) -> str: ...
