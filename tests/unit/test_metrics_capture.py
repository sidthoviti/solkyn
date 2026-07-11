""" Tests for the paper-grade metric-capture surface.

Exercises the LLMManager's cumulative cache/cost/refusal counters,
``effective_params()`` introspection, and seed plumbing. All tests are
fully offline \u2014 ``client.chat.completions.create`` is monkey-patched.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from solkyn.llm.manager import (
    REFUSAL_PATTERNS,
    SEED_SUPPORTING_PROVIDERS,
    LLMManager,
)


def _fake_response(*, content, prompt_tokens=10, completion_tokens=5,
                  cost=None, cached_tokens=0, tool_calls=None):
    usage_kwargs = {
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "prompt_tokens_details": SimpleNamespace(cached_tokens=cached_tokens),
    }
    if cost is not None:
        usage_kwargs["cost"] = cost
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(
            content=content, tool_calls=tool_calls,
        ))],
        usage=SimpleNamespace(**usage_kwargs),
    )


# --- Refusal regex --------------------------------------------------------

class TestRefusalRegex:
    @pytest.mark.parametrize("text", [
        "I can't help with that request.",
        "I cannot assist with hacking activities.",
        "I won't comply with this.",
        "I'm not going to provide instructions for that.",
        "That goes against my guidelines.",
        "I'm not able to assist with that.",
        "I must decline this request.",
        "I will not help you exploit that.",
        "I refuse to provide such information.",
    ])
    def test_refusal_phrases_match(self, text):
        assert REFUSAL_PATTERNS.search(text) is not None

    @pytest.mark.parametrize("text", [
        "Let me try a different approach to enumerate the endpoints.",
        "The flag is FLAG{abc123}. Mission complete.",
        "I'll run nmap to scan the target.",
        "Here is the SQL injection payload that worked.",
        "",
    ])
    def test_benign_text_does_not_match(self, text):
        assert REFUSAL_PATTERNS.search(text) is None


# --- Cumulative LLMManager counters --------------------------------------

class TestCumulativeUsageCounters:
    def _mgr(self, **kw):
        return LLMManager(provider="openrouter", model="x", api_key="test-openrouter-key", **kw)

    def test_cache_read_accumulates(self):
        mgr = self._mgr()
        mgr._client.chat.completions.create = MagicMock(side_effect=[
            _fake_response(content="ok", prompt_tokens=100, cached_tokens=80),
            _fake_response(content="ok", prompt_tokens=200, cached_tokens=150),
        ])
        mgr.chat([{"role": "user", "content": "a"}])
        mgr.chat([{"role": "user", "content": "b"}])
        u = mgr.get_usage()
        assert u["cache_read_input_tokens"] == 230
        assert u["input_tokens"] == 300

    def test_upstream_cost_accumulates_when_present(self):
        mgr = self._mgr()
        mgr._client.chat.completions.create = MagicMock(side_effect=[
            _fake_response(content="ok", cost=0.10),
            _fake_response(content="ok", cost=0.25),
        ])
        mgr.chat([{"role": "user", "content": "a"}])
        mgr.chat([{"role": "user", "content": "b"}])
        assert mgr.get_usage()["upstream_cost_usd"] == pytest.approx(0.35)

    def test_upstream_cost_remains_none_when_provider_omits(self):
        mgr = LLMManager(provider="openai", model="gpt-4o", api_key="test-openai-key")
        mgr._client.chat.completions.create = MagicMock(
            return_value=_fake_response(content="ok", cost=None),
        )
        mgr.chat([{"role": "user", "content": "a"}])
        # None signals "no upstream cost capture available", which is
        # distinct from 0.0 (which would imply free calls).
        assert mgr.get_usage()["upstream_cost_usd"] is None

    def test_refusal_count_increments(self):
        mgr = self._mgr()
        mgr._client.chat.completions.create = MagicMock(side_effect=[
            _fake_response(content="I cannot help with that."),
            _fake_response(content="Let me run nmap."),
            _fake_response(content="I won't comply with this."),
        ])
        for msg in ["a", "b", "c"]:
            mgr.chat([{"role": "user", "content": msg}])
        assert mgr.get_usage()["refusal_count"] == 2

    def test_refusal_count_skips_none_content(self):
        mgr = self._mgr()
        # Tool-call-only response with content=None must not crash the
        # refusal regex path.
        mgr._client.chat.completions.create = MagicMock(
            return_value=_fake_response(content=None),
        )
        mgr.chat([{"role": "user", "content": "a"}])
        assert mgr.get_usage()["refusal_count"] == 0


# --- effective_params ----------------------------------------------------

class TestEffectiveParams:
    def test_modern_openai_uses_max_completion_tokens(self):
        mgr = LLMManager(provider="openai", model="gpt-5.4", api_key="test-openai-key",
                         max_tokens=1234)
        params = mgr.effective_params()
        assert params["max_tokens_field"] == "max_completion_tokens"
        assert params["max_tokens_value"] == 1234

    def test_legacy_openai_uses_max_tokens(self):
        mgr = LLMManager(provider="openai", model="gpt-4o", api_key="test-openai-key")
        assert mgr.effective_params()["max_tokens_field"] == "max_tokens"

    def test_anthropic_always_max_tokens(self):
        mgr = LLMManager(provider="anthropic", model="claude-sonnet-4-20250514",
                         api_key="test-anthropic-key")
        params = mgr.effective_params()
        assert params["max_tokens_field"] == "max_tokens"
        assert params["seed_supported"] is False

    def test_openrouter_seed_supported(self):
        mgr = LLMManager(provider="openrouter", model="anthropic/claude-opus-4.7",
                         api_key="test-openrouter-key", seed=42)
        params = mgr.effective_params()
        assert params["seed_supported"] is True
        assert params["seed"] == 42

    def test_seed_none_when_unsupported_provider(self):
        # Note: lm-studio is NOT in SEED_SUPPORTING_PROVIDERS even
        # though some local backends accept seed; effective_params
        # honestly reports "no, we don't send it".
        mgr = LLMManager(provider="lm-studio", model="x",
                         base_url="http://localhost:1234/v1", seed=42)
        assert mgr.effective_params()["seed_supported"] is False


# --- Seed plumbing into the request --------------------------------------

class TestSeedPlumbing:
    def test_seed_forwarded_for_openrouter(self):
        mgr = LLMManager(provider="openrouter", model="x", api_key="test-openrouter-key",
                         seed=42)
        fake = MagicMock(return_value=_fake_response(content="ok"))
        mgr._client.chat.completions.create = fake
        mgr.chat([{"role": "user", "content": "a"}])
        assert fake.call_args.kwargs["seed"] == 42

    def test_seed_forwarded_for_openai(self):
        mgr = LLMManager(provider="openai", model="gpt-4o", api_key="test-openai-key",
                         seed=7)
        fake = MagicMock(return_value=_fake_response(content="ok"))
        mgr._client.chat.completions.create = fake
        mgr.chat([{"role": "user", "content": "a"}])
        assert fake.call_args.kwargs["seed"] == 7

    def test_seed_omitted_for_local_backend(self):
        # lm-studio etc. are not in SEED_SUPPORTING_PROVIDERS so seed
        # must not appear in the request kwargs.
        mgr = LLMManager(provider="lm-studio", model="x",
                         base_url="http://localhost:1234/v1", seed=42)
        fake = MagicMock(return_value=_fake_response(content="ok"))
        mgr._client.chat.completions.create = fake
        mgr.chat([{"role": "user", "content": "a"}])
        assert "seed" not in fake.call_args.kwargs

    def test_seed_none_means_no_kwarg(self):
        mgr = LLMManager(provider="openrouter", model="x", api_key="test-openrouter-key")
        fake = MagicMock(return_value=_fake_response(content="ok"))
        mgr._client.chat.completions.create = fake
        mgr.chat([{"role": "user", "content": "a"}])
        assert "seed" not in fake.call_args.kwargs


# --- Sanity on the support set -------------------------------------------

class TestSeedSupportSet:
    def test_known_supporting_providers(self):
        assert "openai" in SEED_SUPPORTING_PROVIDERS
        assert "openrouter" in SEED_SUPPORTING_PROVIDERS
        assert "azure" in SEED_SUPPORTING_PROVIDERS
        assert "openai-compatible" in SEED_SUPPORTING_PROVIDERS

    def test_anthropic_not_in_set(self):
        assert "anthropic" not in SEED_SUPPORTING_PROVIDERS
