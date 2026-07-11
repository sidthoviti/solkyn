"""Unit tests for LLM layer — manager, config, and tools."""

from __future__ import annotations

import json
import os
import tempfile

import pytest

from solkyn.llm.config import ProviderConfig, create_llm_from_config, load_models_config
from solkyn.llm.manager import OPENAI_COMPATIBLE_PROVIDERS, LLMManager
from solkyn.llm.tools import build_assistant_message_with_tool_calls, build_tool_result_message, make_tool_schema

# --- ProviderConfig tests ---

class TestProviderConfig:
    def test_basic_config(self):
        pc = ProviderConfig(provider="openai", model="gpt-4o", api_key="test-openai-key")
        assert pc.provider == "openai"
        assert pc.model == "gpt-4o"
        assert pc.api_key == "test-openai-key"

    def test_env_var_resolution(self, monkeypatch):
        monkeypatch.setenv("TEST_API_KEY", "resolved-key-123")
        pc = ProviderConfig(provider="openai", model="gpt-4o", api_key="${TEST_API_KEY}")
        assert pc.api_key == "resolved-key-123"

    def test_env_var_missing_returns_none(self):
        # Unset env vars should resolve to None (lazy — error at usage time)
        os.environ.pop("NONEXISTENT_KEY_XYZ", None)
        pc = ProviderConfig(provider="openai", model="gpt-4o", api_key="${NONEXISTENT_KEY_XYZ}")
        assert pc.api_key is None

    def test_no_api_key(self):
        pc = ProviderConfig(provider="openai", model="gemma-4", base_url="http://localhost:1234/v1")
        assert pc.api_key is None

    def test_defaults(self):
        pc = ProviderConfig(provider="openai", model="gpt-4o")
        assert pc.temperature == 0.0
        assert pc.max_tokens == 4096


# --- LLMManager creation tests ---

class TestLLMManagerCreation:
    def test_openai_provider(self):
        mgr = LLMManager(provider="openai", model="gpt-4o", api_key="test-openai-key")
        assert mgr._provider_type == "openai"
        assert mgr.model == "gpt-4o"

    def test_lm_studio_provider(self):
        mgr = LLMManager(provider="lm-studio", model="gemma-4", base_url="http://localhost:1234/v1")
        assert mgr._provider_type == "openai"

    def test_ollama_provider(self):
        mgr = LLMManager(provider="ollama", model="llama3", base_url="http://localhost:11434/v1")
        assert mgr._provider_type == "openai"

    def test_anthropic_provider(self):
        mgr = LLMManager(provider="anthropic", model="claude-sonnet-4-20250514", api_key="test-anthropic-key")
        assert mgr._provider_type == "anthropic"

    def test_unknown_provider_raises(self):
        with pytest.raises(ValueError, match="Unknown provider"):
            LLMManager(provider="invalid-provider", model="test")

    def test_all_openai_compatible_providers(self):
        for provider in OPENAI_COMPATIBLE_PROVIDERS:
            if provider == "azure":
                continue  # Azure needs special kwargs
            mgr = LLMManager(provider=provider, model="test", base_url="http://localhost:8080/v1")
            assert mgr._provider_type == "openai"

    def test_base_url_passed_to_openai_client(self):
        mgr = LLMManager(provider="openai", model="test", base_url="http://custom:8080/v1", api_key="test")
        assert mgr._client.base_url.host == "custom"


# --- Config loading tests ---

class TestConfigLoading:
    def _make_config_file(self, content: str) -> str:
        """Write config to a temp file and return path."""
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
        f.write(content)
        f.close()
        return f.name

    def test_load_default_config(self):
        config_path = self._make_config_file("""
models:
  default: lm-studio
  providers:
    lm-studio:
      provider: openai
      model: gemma-4
      base_url: "http://localhost:1234/v1"
      temperature: 0.0
      max_tokens: 4096
    openai-gpt4o:
      provider: openai
      model: gpt-4o
      api_key: "test-openai-key"
""")
        config = load_models_config(config_path)
        assert config.default == "lm-studio"
        assert "lm-studio" in config.providers
        assert "openai-gpt4o" in config.providers
        assert config.providers["lm-studio"].base_url == "http://localhost:1234/v1"
        os.unlink(config_path)

    def test_create_llm_from_config(self):
        config_path = self._make_config_file("""
models:
  default: test-provider
  providers:
    test-provider:
      provider: openai
      model: test-model
      base_url: "http://localhost:9999/v1"
""")
        mgr = create_llm_from_config(config_path)
        assert mgr.model == "test-model"
        assert mgr._provider_type == "openai"
        os.unlink(config_path)

    def test_create_llm_specific_provider(self):
        config_path = self._make_config_file("""
models:
  default: provider-a
  providers:
    provider-a:
      provider: openai
      model: model-a
      base_url: "http://localhost:1111/v1"
    provider-b:
      provider: openai
      model: model-b
      base_url: "http://localhost:2222/v1"
""")
        mgr = create_llm_from_config(config_path, provider_name="provider-b")
        assert mgr.model == "model-b"
        os.unlink(config_path)

    def test_missing_provider_raises(self):
        config_path = self._make_config_file("""
models:
  default: nonexistent
  providers:
    real-one:
      provider: openai
      model: test
""")
        with pytest.raises(ValueError, match="not found in config"):
            create_llm_from_config(config_path)
        os.unlink(config_path)

    def test_no_models_section_raises(self):
        config_path = self._make_config_file("agent:\n  timeout: 60\n")
        with pytest.raises(ValueError, match="No 'models' section"):
            load_models_config(config_path)
        os.unlink(config_path)

    def test_env_var_in_config(self, monkeypatch):
        monkeypatch.setenv("MY_TEST_KEY", "secret-123")
        config_path = self._make_config_file("""
models:
  default: test
  providers:
    test:
      provider: openai
      model: gpt-4o
      api_key: "${MY_TEST_KEY}"
""")
        mgr = create_llm_from_config(config_path)
        # The api_key should have been resolved
        assert mgr._client.api_key == "secret-123"
        os.unlink(config_path)


# --- Tool schema tests ---

class TestToolSchemas:
    def test_make_tool_schema(self):
        schema = make_tool_schema(
            name="bash_exec",
            description="Execute a command",
            parameters={
                "type": "object",
                "properties": {"command": {"type": "string", "description": "The command to run"}},
                "required": ["command"],
            },
        )
        assert schema["type"] == "function"
        assert schema["function"]["name"] == "bash_exec"
        assert "command" in schema["function"]["parameters"]["properties"]

    def test_tool_result_message(self):
        msg = build_tool_result_message("call-123", "hello world")
        assert msg["role"] == "tool"
        assert msg["tool_call_id"] == "call-123"
        assert msg["content"] == "hello world"

    def test_assistant_message_with_tool_calls(self):
        msg = build_assistant_message_with_tool_calls(
            content="Let me check that.",
            tool_calls=[{"id": "tc-1", "name": "bash_exec", "arguments": {"command": "ls"}}],
        )
        assert msg["role"] == "assistant"
        assert msg["content"] == "Let me check that."
        assert len(msg["tool_calls"]) == 1
        assert msg["tool_calls"][0]["function"]["name"] == "bash_exec"
        assert json.loads(msg["tool_calls"][0]["function"]["arguments"]) == {"command": "ls"}

    def test_assistant_message_no_content(self):
        msg = build_assistant_message_with_tool_calls(
            content=None,
            tool_calls=[{"id": "tc-1", "name": "bash_exec", "arguments": {"command": "id"}}],
        )
        assert msg["content"] == ""


# --- Token tracking tests ---

class TestTokenTracking:
    def test_usage_starts_at_zero(self):
        mgr = LLMManager(provider="openai", model="test", base_url="http://localhost:1/v1")
        usage = mgr.get_usage()
        assert usage["input_tokens"] == 0
        assert usage["output_tokens"] == 0
