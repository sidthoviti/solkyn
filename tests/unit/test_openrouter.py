""" Offline tests for the OpenRouter provider integration.

These tests must NOT make any live network calls. The OpenAI client is
constructed for real (so we can assert headers / base_url wiring), but
``client.chat.completions.create`` is monkey-patched onto a fake that
returns a fixed response object.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from solkyn.llm.config import (
    ProviderConfig,
    create_llm_from_config,
    load_models_config,
)
from solkyn.llm.manager import (
    OPENAI_COMPATIBLE_PROVIDERS,
    OPENROUTER_DEFAULT_BASE_URL,
    OPENROUTER_DEFAULT_HEADERS,
    LLMManager,
)

# --- Constructor wiring -------------------------------------------------

class TestOpenRouterConstructor:
    def test_openrouter_in_compatible_providers_set(self):
        assert "openrouter" in OPENAI_COMPATIBLE_PROVIDERS

    def test_openrouter_default_base_url(self):
        mgr = LLMManager(provider="openrouter", model="anthropic/claude-opus-4.7",
                         api_key="test-openrouter-key")
        # The OpenAI SDK appends a trailing slash, so compare host+path.
        assert str(mgr._client.base_url).rstrip("/") == OPENROUTER_DEFAULT_BASE_URL

    def test_openrouter_explicit_base_url_overrides_default(self):
        mgr = LLMManager(provider="openrouter", model="x", api_key="test-openrouter-key",
                         base_url="https://example.com/v1")
        assert "example.com" in str(mgr._client.base_url)

    def test_openrouter_attribution_headers_set(self):
        mgr = LLMManager(provider="openrouter", model="x", api_key="test-openrouter-key")
        # The OpenAI SDK exposes default headers via ``_client.default_headers``
        # (lower-cased dict-like). Both attribution headers must be present.
        headers = {k.lower(): v for k, v in mgr._client.default_headers.items()}
        assert headers.get("http-referer") == OPENROUTER_DEFAULT_HEADERS["HTTP-Referer"]
        assert headers.get("x-title") == OPENROUTER_DEFAULT_HEADERS["X-Title"]

    def test_extra_body_stored_on_manager(self):
        eb = {"provider": {"order": ["anthropic"], "allow_fallbacks": False}}
        mgr = LLMManager(provider="openrouter", model="x", api_key="test-openrouter-key",
                         extra_body=eb)
        assert mgr.extra_body == eb

    def test_extra_body_default_none(self):
        mgr = LLMManager(provider="openai", model="gpt-4o", api_key="test-openai-key")
        assert mgr.extra_body is None


# --- chat() forwarding & cost capture -----------------------------------

def _make_fake_response(*, content: str, prompt_tokens: int, completion_tokens: int,
                       cost: float | None = None, cached_tokens: int = 0):
    """Build a duck-typed object matching the subset of the OpenAI
    response surface used by ``_chat_openai``."""
    usage_kwargs: dict = {
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "prompt_tokens_details": SimpleNamespace(cached_tokens=cached_tokens),
    }
    if cost is not None:
        usage_kwargs["cost"] = cost
    usage = SimpleNamespace(**usage_kwargs)
    message = SimpleNamespace(content=content, tool_calls=None)
    choice = SimpleNamespace(message=message)
    return SimpleNamespace(choices=[choice], usage=usage)


class TestOpenRouterChat:
    def test_extra_body_forwarded_to_create(self):
        eb = {"provider": {"order": ["anthropic"], "allow_fallbacks": False}}
        mgr = LLMManager(provider="openrouter", model="anthropic/claude-opus-4.7",
                         api_key="test-openrouter-key", extra_body=eb)
        fake_create = MagicMock(return_value=_make_fake_response(
            content="ok", prompt_tokens=10, completion_tokens=5, cost=0.0001,
        ))
        mgr._client.chat.completions.create = fake_create
        mgr.chat([{"role": "user", "content": "hi"}])

        kwargs = fake_create.call_args.kwargs
        assert kwargs["extra_body"] == eb
        assert kwargs["model"] == "anthropic/claude-opus-4.7"

    def test_no_extra_body_means_no_extra_body_kwarg(self):
        mgr = LLMManager(provider="openrouter", model="x", api_key="test-openrouter-key")
        fake_create = MagicMock(return_value=_make_fake_response(
            content="ok", prompt_tokens=1, completion_tokens=1,
        ))
        mgr._client.chat.completions.create = fake_create
        mgr.chat([{"role": "user", "content": "hi"}])

        # When extra_body is None we must NOT pass an empty dict (the
        # SDK treats absent vs empty differently for some endpoints).
        assert "extra_body" not in fake_create.call_args.kwargs

    def test_upstream_cost_captured(self):
        mgr = LLMManager(provider="openrouter", model="anthropic/claude-opus-4.7",
                         api_key="test-openrouter-key")
        mgr._client.chat.completions.create = MagicMock(
            return_value=_make_fake_response(
                content="ok", prompt_tokens=100, completion_tokens=50, cost=0.42,
            )
        )
        result = mgr.chat([{"role": "user", "content": "hi"}])
        assert result["usage"]["upstream_cost_usd"] == 0.42
        assert result["usage"]["input_tokens"] == 100
        assert result["usage"]["output_tokens"] == 50

    def test_upstream_cost_absent_when_provider_omits_it(self):
        # OpenAI / Azure / other compatible providers do NOT return
        # ``response.usage.cost`` \u2014 the field must simply be absent
        # from our usage dict, not zero (zero would imply a free call).
        mgr = LLMManager(provider="openai", model="gpt-4o", api_key="test-openai-key")
        mgr._client.chat.completions.create = MagicMock(
            return_value=_make_fake_response(
                content="ok", prompt_tokens=10, completion_tokens=5, cost=None,
            )
        )
        result = mgr.chat([{"role": "user", "content": "hi"}])
        assert "upstream_cost_usd" not in result["usage"]


# --- ProviderConfig + factory wiring ------------------------------------

class TestOpenRouterProviderConfig:
    def test_extra_body_field_default_none(self):
        pc = ProviderConfig(provider="openrouter", model="x", api_key="test-openrouter-key")
        assert pc.extra_body is None

    def test_extra_body_field_accepts_dict(self):
        eb = {"provider": {"order": ["anthropic"]}}
        pc = ProviderConfig(provider="openrouter", model="x", api_key="test-openrouter-key",
                            extra_body=eb)
        assert pc.extra_body == eb

    def test_default_yaml_has_openrouter_opus47(self):
        # Smoke test the shipped config so a future YAML edit can't
        # silently drop the Opus 4.7 entry.
        cfg = load_models_config("configs/default.yaml")
        assert "openrouter-opus47" in cfg.providers
        opus = cfg.providers["openrouter-opus47"]
        assert opus.provider == "openrouter"
        assert opus.model == "anthropic/claude-opus-4.7"
        assert opus.max_tokens == 8192
        assert opus.extra_body is not None
        assert opus.extra_body["provider"]["allow_fallbacks"] is False
        assert opus.extra_body["provider"]["order"] == ["anthropic"]

    def test_factory_plumbs_extra_body_into_manager(self, monkeypatch):
        monkeypatch.setenv("OPENROUTER_API_KEY", "test-openrouter-key")
        mgr = create_llm_from_config("configs/default.yaml", "openrouter-opus47")
        assert mgr.provider == "openrouter"
        assert mgr.extra_body is not None
        assert mgr.extra_body["provider"]["order"] == ["anthropic"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
