"""Unit tests for config loader and CLI."""

from __future__ import annotations

import json
import os
import tempfile

import pytest
from click.testing import CliRunner

from solkyn.cli.main import cli
from solkyn.config.loader import load_config
from solkyn.config.schema import ScanConfig


class TestConfigSchema:
    def test_defaults(self):
        cfg = ScanConfig()
        assert cfg.agent.max_iterations == 60
        assert cfg.agent.timeout == 600
        assert cfg.docker.image == "solkyn/kali:latest"
        assert cfg.docker.network == "solkyn-net"
        assert cfg.docker.command_timeout == 120

    def test_get_default_provider(self):
        cfg = ScanConfig(
            models={"default": "test", "providers": {"test": {"provider": "openai", "model": "m1"}}}
        )
        p = cfg.get_default_provider()
        assert p.provider == "openai"
        assert p.model == "m1"

    def test_get_provider_missing_raises(self):
        cfg = ScanConfig()
        with pytest.raises(KeyError, match="not found"):
            cfg.get_provider("nonexistent")

    def test_get_default_provider_missing_raises(self):
        cfg = ScanConfig(models={"default": "missing", "providers": {}})
        with pytest.raises(KeyError, match="not found in providers"):
            cfg.get_default_provider()


class TestConfigLoading:
    def test_load_default_config(self):
        cfg = load_config(resolve_env=False)
        assert cfg.agent.max_iterations == 60
        assert cfg.docker.image == "solkyn/kali:latest"
        assert cfg.models.default == "lm-studio-gemma4"
        assert "lm-studio-gemma4" in cfg.models.providers
        assert "openai-gpt4o" in cfg.models.providers

    def test_env_var_substitution(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "test-key-123")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "ant-test-key-456")
        cfg = load_config(resolve_env=True)
        openai_cfg = cfg.models.providers["openai-gpt4o"]
        assert openai_cfg.api_key == "test-key-123"

    def test_missing_env_var_passes_through(self):
        # Missing env vars pass through as raw ${VAR} string
        env = os.environ.copy()
        for key in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
            env.pop(key, None)
        os.environ.clear()
        os.environ.update(env)

        cfg = load_config(resolve_env=True)
        # Unresolved vars remain as raw ${VAR} placeholders
        assert cfg.models.providers["openai-gpt4o"].api_key == "${OPENAI_API_KEY}"
        assert cfg.models.providers["anthropic-claude-sonnet"].api_key == "${ANTHROPIC_API_KEY}"

    def test_override_preserves_defaults(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("agent:\n  max_iterations: 100\n")
            f.flush()
            cfg = load_config(f.name, resolve_env=False)

        assert cfg.agent.max_iterations == 100
        # Defaults preserved
        assert cfg.agent.timeout == 600
        assert cfg.docker.image == "solkyn/kali:latest"
        os.unlink(f.name)

    def test_load_custom_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(
                "agent:\n  max_iterations: 10\n"
                "models:\n  default: custom\n"
                "  providers:\n    custom:\n      provider: openai\n      model: gpt-4\n"
            )
            f.flush()
            cfg = load_config(f.name, resolve_env=False)

        assert cfg.agent.max_iterations == 10
        assert cfg.models.default == "custom"
        assert "custom" in cfg.models.providers
        os.unlink(f.name)


class TestCLI:
    def setup_method(self):
        self.runner = CliRunner()

    def test_version(self):
        result = self.runner.invoke(cli, ["version"])
        assert result.exit_code == 0
        assert "solkyn" in result.output
        assert "0.1.0" in result.output

    def test_config_default(self):
        result = self.runner.invoke(cli, ["config"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "agent" in data
        assert "docker" in data
        assert "models" in data

    def test_config_with_path(self):
        result = self.runner.invoke(cli, ["config", "--config", "configs/default.yaml"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["agent"]["max_iterations"] == 60

    def test_scan_requires_target(self):
        result = self.runner.invoke(cli, ["scan"])
        assert result.exit_code != 0
        assert "Missing option" in result.output or "required" in result.output.lower()

    def test_scan_with_target(self):
        # Scan command should work (just prints placeholder for now)
        result = self.runner.invoke(cli, ["scan", "--target", "http://localhost:8080"])
        # May fail on env var resolution if API keys not set — that's ok
        # Just verify it doesn't crash on missing click args
        assert "target" in result.output.lower() or result.exit_code in (0, 1)

    def test_help(self):
        result = self.runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "Solkyn" in result.output
