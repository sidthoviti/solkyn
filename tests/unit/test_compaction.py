""" SingleLoopCompactSolver: threshold-triggered conversation compaction."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from solkyn.agents.solvers.single_loop_compact import (
    SingleLoopCompactSolver,
    _contains_flag,
    _estimate_tokens,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mk_llm(content: str = "summary text"):
    llm = MagicMock()
    llm.chat.return_value = {"content": content, "tool_calls": None,
                             "usage": {"input_tokens": 0, "output_tokens": 0}}
    return llm


def _mk_solver(**overrides):
    llm = _mk_llm()
    defaults = dict(
        llm_manager=llm, tool_schemas=None,
        compaction_threshold_pct=0.7,
        model_context_window=1000,  # tiny window so threshold = 700 tokens
        preserve_tail_messages=4,
    )
    defaults.update(overrides)
    return SingleLoopCompactSolver(**defaults), llm


# ---------------------------------------------------------------------------
# Construction validation
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_rejects_bad_threshold(self) -> None:
        with pytest.raises(ValueError):
            _mk_solver(compaction_threshold_pct=1.5)
        with pytest.raises(ValueError):
            _mk_solver(compaction_threshold_pct=0.0)

    def test_rejects_zero_window(self) -> None:
        with pytest.raises(ValueError):
            _mk_solver(model_context_window=0)

    def test_rejects_too_small_tail(self) -> None:
        with pytest.raises(ValueError):
            _mk_solver(preserve_tail_messages=1)


# ---------------------------------------------------------------------------
# Token estimator + flag detector
# ---------------------------------------------------------------------------


class TestEstimator:
    def test_grows_with_content(self) -> None:
        a = _estimate_tokens([{"role": "user", "content": "hi"}])
        b = _estimate_tokens([{"role": "user", "content": "x" * 1000}])
        assert b > a * 5  # roughly proportional

    def test_handles_non_serialisable(self) -> None:
        class Weird:
            pass
        n = _estimate_tokens([{"role": "user", "content": Weird()}])
        assert n > 0


class TestFlagDetection:
    def test_string_content(self) -> None:
        assert _contains_flag({"role": "user", "content": "got FLAG{abc}"})
        assert not _contains_flag({"role": "user", "content": "no flag here"})

    def test_lowercase_flag(self) -> None:
        assert _contains_flag({"role": "user", "content": "flag{xyz}"})

    def test_in_tool_call_args(self) -> None:
        msg = {"role": "assistant", "content": "running",
               "tool_calls": [{"name": "exec", "arguments": {"cmd": "echo FLAG{abc}"}}]}
        assert _contains_flag(msg)

    def test_in_list_content(self) -> None:
        msg = {"role": "user", "content": [{"type": "text", "text": "FLAG{xyz}"}]}
        assert _contains_flag(msg)


# ---------------------------------------------------------------------------
# Compaction trigger
# ---------------------------------------------------------------------------


class TestCompactionTrigger:
    def test_no_compaction_below_threshold(self) -> None:
        s, llm = _mk_solver()
        s.messages = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "hi"},
        ]
        assert s._maybe_compact() is False
        assert s.compaction_count == 0
        llm.chat.assert_not_called()

    def test_compacts_above_threshold(self) -> None:
        s, llm = _mk_solver()
        # Build a conversation well over 700 tokens.
        s.messages = [{"role": "system", "content": "sys"}]
        for i in range(20):
            s.messages.append({"role": "assistant", "content": "x" * 500,
                               "tool_calls": [{"name": "t", "arguments": {"a": i}}]})
            s.messages.append({"role": "tool", "content": "result " + "y" * 500})
        assert _estimate_tokens(s.messages) > 700
        before_n = len(s.messages)

        compacted = s._maybe_compact()
        assert compacted is True
        assert s.compaction_count == 1
        # Token count dropped.
        before_est, after_est = s.last_compaction_estimate
        assert after_est < before_est
        # Message count dropped.
        assert len(s.messages) < before_n
        # System message preserved.
        assert s.messages[0]["role"] == "system"
        # Synthetic summary present.
        assert any(
            "Conversation Summary (compacted)" in (m.get("content") or "")
            for m in s.messages
        )
        # Summariser was called once.
        assert llm.chat.call_count == 1

    def test_skips_when_only_tail_messages_present(self) -> None:
        s, _ = _mk_solver(preserve_tail_messages=4)
        # 1 system + 4 tail = nothing in middle to compact.
        s.messages = [{"role": "system", "content": "x" * 5000}]
        for _ in range(4):
            s.messages.append({"role": "user", "content": "x" * 5000})
        assert _estimate_tokens(s.messages) > 700
        assert s._maybe_compact() is False


# ---------------------------------------------------------------------------
# Preservation invariants
# ---------------------------------------------------------------------------


class TestPreservation:
    def test_system_prompt_always_first(self) -> None:
        s, _ = _mk_solver()
        s.messages = [{"role": "system", "content": "SYS_MARKER"}]
        for i in range(20):
            s.messages.append({"role": "user", "content": "x" * 500})
        s._maybe_compact()
        assert s.messages[0]["role"] == "system"
        assert "SYS_MARKER" in s.messages[0]["content"]

    def test_last_n_messages_preserved_verbatim(self) -> None:
        s, _ = _mk_solver(preserve_tail_messages=4)
        s.messages = [{"role": "system", "content": "sys"}]
        for i in range(20):
            s.messages.append({"role": "user", "content": "x" * 500 + f"_{i}"})
        # Capture tail BEFORE compaction
        tail_before = s.messages[-4:]
        s._maybe_compact()
        # Last 4 messages should be the same objects (preserved verbatim).
        assert s.messages[-4:] == tail_before

    def test_flag_bearing_messages_never_compacted(self) -> None:
        s, _ = _mk_solver(preserve_tail_messages=4)
        s.messages = [{"role": "system", "content": "sys"}]
        # Inject a flag-bearing message early in the conversation.
        s.messages.append({"role": "tool", "content": "found FLAG{secret_keep_me}"})
        for i in range(20):
            s.messages.append({"role": "user", "content": "x" * 500})
        s._maybe_compact()
        # Flag content must survive somewhere in the messages list.
        assert any(
            "FLAG{secret_keep_me}" in (m.get("content") or "")
            for m in s.messages
        )


# ---------------------------------------------------------------------------
# Summariser fallback
# ---------------------------------------------------------------------------


class TestSummariserFallback:
    def test_llm_failure_uses_stub(self) -> None:
        llm = _mk_llm()
        llm.chat.side_effect = RuntimeError("api down")
        s = SingleLoopCompactSolver(
            llm_manager=llm, tool_schemas=None,
            model_context_window=1000, compaction_threshold_pct=0.7,
            preserve_tail_messages=4,
        )
        s.messages = [{"role": "system", "content": "sys"}]
        for i in range(20):
            s.messages.append({"role": "user", "content": "x" * 500})
        # Compaction proceeds; stub summary used; no exception leaks.
        assert s._maybe_compact() is True
        # Synthetic summary still present (with stub text).
        assert any(
            "summariser unavailable" in (m.get("content") or "").lower()
            for m in s.messages
        )


# ---------------------------------------------------------------------------
# Integration via SolverAgent --solver flag wiring
# ---------------------------------------------------------------------------


class TestSolverAgentWiring:
    def test_unknown_solver_name_rejected(self) -> None:
        from unittest.mock import MagicMock as _M

        from solkyn.agents.solver import SolverAgent
        from solkyn.tools.registry import ToolRegistry
        with pytest.raises(ValueError):
            SolverAgent(
                llm_manager=_M(), tool_registry=ToolRegistry(),
                solver_name="bogus",
            )

    def test_default_solver_is_single_loop(self) -> None:
        from unittest.mock import MagicMock as _M

        from solkyn.agents.solver import SolverAgent
        from solkyn.tools.registry import ToolRegistry
        agent = SolverAgent(llm_manager=_M(), tool_registry=ToolRegistry())
        assert agent._solver_name == "single_loop"

    def test_compact_solver_name_accepted(self) -> None:
        from unittest.mock import MagicMock as _M

        from solkyn.agents.solver import SolverAgent
        from solkyn.tools.registry import ToolRegistry
        agent = SolverAgent(
            llm_manager=_M(), tool_registry=ToolRegistry(),
            solver_name="single_loop_compact",
        )
        assert agent._solver_name == "single_loop_compact"
