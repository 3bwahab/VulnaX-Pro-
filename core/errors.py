"""Typed exception hierarchy."""
from __future__ import annotations


class VulnaXError(Exception):
    """Base for all framework errors."""


class ConfigError(VulnaXError):
    pass


class ScopeError(VulnaXError):
    pass


class ScopeViolation(VulnaXError):
    pass


class ToolNotFound(VulnaXError):
    pass


class ToolTimeout(VulnaXError):
    pass


class AdapterParseError(VulnaXError):
    pass


class EngineError(VulnaXError):
    pass
