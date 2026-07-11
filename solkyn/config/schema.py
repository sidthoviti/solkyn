"""Pydantic schema models for Solkyn scan configuration."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field


class TargetConfig(BaseModel):
    """Target specification."""

    url: str = ""
    type: str = "web"
    platform: str = "standalone"


class ModelProviderConfig(BaseModel):
    """Single model provider configuration."""

    provider: str
    model: str
    api_key: str | None = None
    base_url: str | None = None
    temperature: float = 0.0
    max_tokens: int = 4096


class ModelsConfig(BaseModel):
    """Models configuration section."""

    default: str = "lm-studio-gemma4"
    providers: dict[str, ModelProviderConfig] = Field(default_factory=dict)


class AgentConfig(BaseModel):
    """Agent behavior configuration."""

    max_iterations: int = 60
    timeout: int = 600
    # Wall-clock and cost budgets. None means unbounded.
    max_time_seconds: float | None = None
    max_cost_usd: float | None = None


class DockerConfig(BaseModel):
    """Docker container configuration."""

    image: str = "solkyn/kali:latest"
    network: str = "solkyn-net"
    command_timeout: int = 120


class ScanConfig(BaseModel):
    """Top-level scan configuration."""

    target: TargetConfig = Field(default_factory=TargetConfig)
    agent: AgentConfig = Field(default_factory=AgentConfig)
    docker: DockerConfig = Field(default_factory=DockerConfig)
    models: ModelsConfig = Field(default_factory=ModelsConfig)
    output_dir: str | None = None

    def get_default_provider(self) -> ModelProviderConfig:
        """Return the default model provider config."""
        name = self.models.default
        if name not in self.models.providers:
            raise KeyError(
                f"Default model '{name}' not found in providers. "
                f"Available: {', '.join(self.models.providers)}"
            )
        return self.models.providers[name]

    def get_provider(self, name: str) -> ModelProviderConfig:
        """Return a specific model provider config by name."""
        if name not in self.models.providers:
            raise KeyError(
                f"Model '{name}' not found. Available: {', '.join(self.models.providers)}"
            )
        return self.models.providers[name]

    @property
    def output_path(self) -> Path:
        """Return the output directory as a Path."""
        if self.output_dir:
            return Path(self.output_dir)
        return Path("scans")
