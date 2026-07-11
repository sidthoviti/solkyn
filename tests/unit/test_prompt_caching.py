"""Anthropic prompt-caching marker tests.

Anthropic / OpenRouter→Anthropic only honour the cache when an
explicit ``cache_control: ephemeral`` marker is set on the system
block. These tests pin that the cache marker is:

  - **emitted** for native Anthropic (`provider="anthropic"`)
  - **emitted** for OpenRouter pinned to an `anthropic/*` model
  - **NOT emitted** when the upstream is OpenAI/Azure/etc.
    (their caching is automatic; an unknown field would be either
    ignored or, worse, rejected by stricter providers)

Plus unit coverage of the pure-function helpers (`_is_anthropic_upstream`,
`_inject_anthropic_cache_marker`) so any future refactor that breaks
the wiring trips a fast unit test rather than wasting provider budget
in a live run.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

from solkyn.llm.manager import LLMManager, _is_anthropic_upstream

# --- _is_anthropic_upstream ---------------------------------------------

class TestIsAnthropicUpstream:
    def test_native_anthropic_is_anthropic_upstream(self):
        assert _is_anthropic_upstream("anthropic", "claude-opus-4-5", None) is True

    def test_openrouter_anthropic_model_is_anthropic_upstream(self):
        assert _is_anthropic_upstream(
            "openrouter", "anthropic/claude-opus-4.7", None
        ) is True

    def test_openrouter_non_anthropic_model_is_not_anthropic_upstream(self):
        assert _is_anthropic_upstream(
            "openrouter", "openai/gpt-5", None
        ) is False

    def test_openai_is_not_anthropic_upstream(self):
        assert _is_anthropic_upstream("openai", "gpt-5", None) is False

    def test_azure_is_not_anthropic_upstream(self):
        assert _is_anthropic_upstream("azure", "gpt-4o", None) is False


# --- _inject_anthropic_cache_marker -------------------------------------

class TestInjectAnthropicCacheMarker:
    def test_wraps_first_system_message_into_block_array(self):
        msgs = [
            {"role": "system", "content": "you are a pentest agent"},
            {"role": "user", "content": "hi"},
        ]
        out = LLMManager._inject_anthropic_cache_marker(msgs)
        sys_msg = out[0]
        assert sys_msg["role"] == "system"
        assert isinstance(sys_msg["content"], list)
        assert sys_msg["content"][0] == {
            "type": "text",
            "text": "you are a pentest agent",
            "cache_control": {"type": "ephemeral"},
        }
        # User message untouched
        assert out[1] == {"role": "user", "content": "hi"}

    def test_does_not_mutate_caller(self):
        msgs = [{"role": "system", "content": "sys"}]
        original_content = msgs[0]["content"]
        LLMManager._inject_anthropic_cache_marker(msgs)
        assert msgs[0]["content"] == original_content
        assert isinstance(msgs[0]["content"], str)

    def test_noop_on_empty_message_list(self):
        assert LLMManager._inject_anthropic_cache_marker([]) == []

    def test_noop_when_no_system_message(self):
        msgs = [{"role": "user", "content": "hi"}]
        assert LLMManager._inject_anthropic_cache_marker(msgs) == msgs

    def test_noop_when_system_content_already_arrayed(self):
        # Caller pre-formatted the system block — assume they know best.
        msgs = [
            {"role": "system", "content": [{"type": "text", "text": "sys"}]},
            {"role": "user", "content": "hi"},
        ]
        out = LLMManager._inject_anthropic_cache_marker(msgs)
        assert out[0]["content"] == [{"type": "text", "text": "sys"}]


# --- _chat_openai cache-marker injection --------------------------------

def _make_fake_openai_response():
    """Minimal duck-typed OpenAI completion response."""
    usage = SimpleNamespace(
        prompt_tokens=10,
        completion_tokens=5,
        prompt_tokens_details=SimpleNamespace(cached_tokens=0),
    )
    message = SimpleNamespace(content="ok", tool_calls=None)
    return SimpleNamespace(choices=[SimpleNamespace(message=message)], usage=usage)


class TestChatOpenAICacheMarker:
    def test_openrouter_anthropic_model_gets_cache_control_marker(self):
        mgr = LLMManager(
            provider="openrouter",
            model="anthropic/claude-opus-4.7",
            api_key="test-openrouter-key",
        )
        fake_create = MagicMock(return_value=_make_fake_openai_response())
        mgr._client.chat.completions.create = fake_create

        mgr.chat([
            {"role": "system", "content": "playbooks etc"},
            {"role": "user", "content": "hi"},
        ])

        sent_messages = fake_create.call_args.kwargs["messages"]
        sys_msg = sent_messages[0]
        assert sys_msg["role"] == "system"
        assert isinstance(sys_msg["content"], list)
        assert sys_msg["content"][0]["cache_control"] == {"type": "ephemeral"}
        assert sys_msg["content"][0]["text"] == "playbooks etc"

    def test_openai_proper_does_not_get_cache_control_marker(self):
        # OpenAI caches automatically; the cache_control field is
        # Anthropic-specific and would be at best ignored.
        mgr = LLMManager(provider="openai", model="gpt-5", api_key="test-openai-key")
        fake_create = MagicMock(return_value=_make_fake_openai_response())
        mgr._client.chat.completions.create = fake_create

        mgr.chat([
            {"role": "system", "content": "playbooks etc"},
            {"role": "user", "content": "hi"},
        ])

        sent_messages = fake_create.call_args.kwargs["messages"]
        sys_msg = sent_messages[0]
        # System message preserved verbatim — string content, no rewrite.
        assert sys_msg == {"role": "system", "content": "playbooks etc"}

    def test_openrouter_non_anthropic_does_not_get_cache_control_marker(self):
        mgr = LLMManager(
            provider="openrouter", model="openai/gpt-5", api_key="test-openrouter-key",
        )
        fake_create = MagicMock(return_value=_make_fake_openai_response())
        mgr._client.chat.completions.create = fake_create

        mgr.chat([
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "hi"},
        ])

        sys_msg = fake_create.call_args.kwargs["messages"][0]
        assert sys_msg == {"role": "system", "content": "sys"}


# --- _chat_anthropic native cache marker --------------------------------

def _make_fake_anthropic_response():
    """Minimal duck-typed Anthropic Message response."""
    usage = SimpleNamespace(
        input_tokens=10,
        output_tokens=5,
        cache_read_input_tokens=0,
        cache_creation_input_tokens=0,
    )
    text_block = SimpleNamespace(type="text", text="ok")
    return SimpleNamespace(content=[text_block], usage=usage)


class TestChatAnthropicCacheMarker:
    def test_native_anthropic_system_uses_block_array_with_cache_control(self):
        mgr = LLMManager(
            provider="anthropic", model="claude-opus-4-5", api_key="test-anthropic-key",
        )
        fake_create = MagicMock(return_value=_make_fake_anthropic_response())
        mgr._client.messages.create = fake_create

        mgr.chat([
            {"role": "system", "content": "long system prompt"},
            {"role": "user", "content": "hi"},
        ])

        sent_system = fake_create.call_args.kwargs["system"]
        assert isinstance(sent_system, list)
        assert sent_system[0] == {
            "type": "text",
            "text": "long system prompt",
            "cache_control": {"type": "ephemeral"},
        }

    def test_native_anthropic_no_system_message_omits_system_kwarg(self):
        mgr = LLMManager(
            provider="anthropic", model="claude-opus-4-5", api_key="test-anthropic-key",
        )
        fake_create = MagicMock(return_value=_make_fake_anthropic_response())
        mgr._client.messages.create = fake_create

        mgr.chat([{"role": "user", "content": "hi"}])

        # No system block at all — caller didn't supply one.
        assert "system" not in fake_create.call_args.kwargs


# --- cost reconciliation helper ------------------------------------------

class TestBuildCostReconciliation:
    """The helper lives in scripts/run_challenges.py so we import via
    the script path. Kept here (not in a separate file) because it's
    intimately tied to the per-call cost telemetry shipped together
    with prompt caching."""

    def _import_helper(self):
        import importlib.util
        from pathlib import Path
        path = Path(__file__).resolve().parents[2] / "scripts" / "run_challenges.py"
        spec = importlib.util.spec_from_file_location("solkyn_runner", path)
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod._build_cost_reconciliation

    def test_returns_none_when_both_inputs_none(self):
        fn = self._import_helper()
        assert fn(None, None) is None

    def test_delta_pct_zero_when_local_equals_upstream(self):
        fn = self._import_helper()
        out = fn(1.0, 1.0)
        assert out == {
            "local_cost_usd": 1.0,
            "upstream_cost_usd": 1.0,
            "delta_pct": 0.0,
        }

    def test_delta_pct_positive_when_local_overestimates(self):
        fn = self._import_helper()
        out = fn(1.10, 1.00)
        assert out["delta_pct"] == 10.0

    def test_delta_pct_negative_when_provider_billed_more(self):
        fn = self._import_helper()
        out = fn(0.90, 1.00)
        assert out["delta_pct"] == -10.0

    def test_delta_pct_none_when_only_one_side_present(self):
        fn = self._import_helper()
        assert fn(1.0, None)["delta_pct"] is None
        assert fn(None, 1.0)["delta_pct"] is None

    def test_delta_pct_none_when_upstream_zero(self):
        fn = self._import_helper()
        # Avoid division by zero — return None rather than inf/NaN.
        assert fn(0.5, 0.0)["delta_pct"] is None
