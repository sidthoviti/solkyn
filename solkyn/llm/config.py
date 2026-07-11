"""LLM configuration models and YAML-based factory."""

from __future__ import annotations

import os
import re

import yaml
from pydantic import BaseModel, field_validator

from solkyn.llm.manager import LLMManager


class ProviderConfig(BaseModel):
    """Configuration for a single LLM provider."""
    provider: str
    model: str
    api_key: str | None = None
    base_url: str | None = None
    temperature: float = 0.0
    max_tokens: int = 4096
    # Vendor-specific kwargs forwarded into the upstream API call
    # via the OpenAI SDK's ``extra_body`` channel. Currently used by
    # OpenRouter for ``{"provider": {"order": [...], "allow_fallbacks": ...}}``
    # routing constraints; safe to leave as ``None`` for every other
    # provider.
    extra_body: dict | None = None
    # Deterministic-ish sampling seed. Forwarded to providers
    # in ``SEED_SUPPORTING_PROVIDERS`` (OpenAI / Azure / OpenRouter /
    # generic openai-compatible); silently ignored elsewhere. Even where
    # supported it is best-effort — not bit-exact.
    seed: int | None = None

    @field_validator("api_key", "base_url", mode="before")
    @classmethod
    def resolve_env_var(cls, v: str | None) -> str | None:
        """Resolve ${VAR_NAME} references to environment variables.

        Returns None if the referenced env var is not set (allows unused
        providers to remain in the config without blocking startup).
        Applies to both api_key and base_url so providers can be fully
        environment-driven.
        """
        if v is None:
            return None
        match = re.fullmatch(r"\$\{(\w+)\}", v)
        if match:
            var_name = match.group(1)
            return os.environ.get(var_name)
        return v


class ModelsConfig(BaseModel):
    """Top-level models configuration."""
    default: str
    providers: dict[str, ProviderConfig]


def load_models_config(config_path: str) -> ModelsConfig:
    """Load models configuration from a YAML file."""
    with open(config_path) as f:
        raw = yaml.safe_load(f)

    models_section = raw.get("models")
    if not models_section:
        raise ValueError(f"No 'models' section in {config_path}")

    return ModelsConfig(**models_section)


def create_llm_from_config(config_path: str, provider_name: str | None = None) -> LLMManager:
    """Create an LLMManager from YAML config.

    Args:
        config_path: Path to YAML config file.
        provider_name: Which provider to use. If None, uses the 'default' from config.

    Returns:
        Configured LLMManager instance.
    """
    models_config = load_models_config(config_path)
    name = provider_name or models_config.default

    if name not in models_config.providers:
        available = ", ".join(models_config.providers.keys())
        raise ValueError(f"Provider '{name}' not found in config. Available: {available}")

    pc = models_config.providers[name]
    return LLMManager(
        provider=pc.provider,
        model=pc.model,
        api_key=pc.api_key,
        base_url=pc.base_url,
        temperature=pc.temperature,
        max_tokens=pc.max_tokens,
        extra_body=pc.extra_body,
        seed=pc.seed,
    )
