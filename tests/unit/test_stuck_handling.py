""" Stuck-handling layer tests.

The orchestrator's stuck-handling fires when the solver returns
``SolverAction(type="none")`` AND the flag has not been found AND there is
iteration budget remaining AND the nudge has not already been used this
attempt. It injects a structured try-harder ``user`` message with the last
1–3 tool-call previews, then loops once more.

Tool-call validation errors are surfaced to the solver as the tool result
text — verified at the orchestrator's existing ``_dispatch_command`` level.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from solkyn.agents.flag_detector import FlagDetector
from solkyn.agents.orchestrator import (
    Orchestrator,
    _build_try_harder_message,
)
from solkyn.agents.solvers.base import SolverAction

# Re-use the StubSolver and _new_action helpers from the existing test module.
from tests.unit.test_orchestrator import StubSolver, _new_action


def _orch(max_iter: int = 5, **kwargs: Any) -> tuple[Orchestrator, MagicMock]:
    tools = MagicMock()
    tools.execute_tool = MagicMock(return_value="tool out")
    return Orchestrator(
        tools=tools,
        flag_detector=FlagDetector(),
        max_iterations=max_iter,
        **kwargs,
    ), tools


class TestTryHarderMessageBuilder:
    def test_no_tool_calls_yet_yields_recon_hint(self) -> None:
        msg = _build_try_harder_message([])
        assert "No tool calls yet" in msg
        assert "reconnaissance" in msg

    def test_includes_recent_tool_calls_truncated(self) -> None:
        log = [
            {"iteration": 1, "tool": "bash_exec", "args": {"command": "id"}},
            {"iteration": 2, "tool": "bash_exec", "args": {"command": "x" * 200}},
            {"iteration": 3, "tool": "bash_exec", "args": {"command": "whoami"}},
        ]
        msg = _build_try_harder_message(log)
        assert "iter 1" in msg and "id" in msg
        assert "iter 3" in msg and "whoami" in msg
        # Long command was truncated to 120 chars + "..."
        assert "x" * 200 not in msg
        assert "..." in msg

    def test_only_last_three_calls_included(self) -> None:
        log = [{"iteration": i, "tool": "bash_exec", "args": {"command": f"cmd{i}"}}
               for i in range(1, 11)]
        msg = _build_try_harder_message(log)
        # Only iterations 8, 9, 10 should appear in the recent context block.
        assert "cmd1)" not in msg
        assert "cmd7)" not in msg
        assert "cmd8)" in msg and "cmd9)" in msg and "cmd10)" in msg


class TestStuckHandlingNudge:
    def test_nudge_fires_once_then_terminates_on_second_none(self) -> None:
        o, _ = _orch()
        s = StubSolver([
            _new_action(),                       # iter 1: real command
            _new_action(type_="none"),           # iter 2: triggers nudge
            _new_action(type_="none"),           # iter 3: terminates
        ])
        r = o.run(s)
        assert r.exit_reason == "no_tool_calls"
        assert r.stuck_recovery_used is True
        assert r.iterations == 3
        # Exactly one nudge injected.
        nudges = [c for c in s.injected if "different approach" in c[1].lower()]
        assert len(nudges) == 1

    def test_nudge_skipped_if_flag_already_found(self) -> None:
        """When the LLM emits the flag in text and then returns no tool
        calls, we must NOT inject a try-harder nudge — the run is done."""
        o, _ = _orch()
        s = StubSolver([
            _new_action(type_="none", flag_in_text="FLAG{deadbeef}"),
        ])
        r = o.run(s)
        assert r.exit_reason == "flag_found"
        assert r.flags_found == ["FLAG{deadbeef}"]
        assert r.stuck_recovery_used is False
        assert s.injected == []

    def test_nudge_skipped_at_max_iterations(self) -> None:
        o, _ = _orch(max_iter=1)
        # Only one iteration is allowed; the cap fires before the nudge.
        s = StubSolver([
            _new_action(),
            _new_action(type_="none"),  # never reached due to cap
        ])
        r = o.run(s)
        assert r.exit_reason == "max_iterations"
        assert r.iterations == 1
        assert r.stuck_recovery_used is False
        assert s.injected == []

    def test_nudge_uses_last_tool_call_context(self) -> None:
        o, tools = _orch()
        tools.execute_tool.return_value = "boring output"
        s = StubSolver([
            _new_action(tool_args={"command": "curl http://target/login"}),
            _new_action(type_="none"),  # triggers nudge with curl context
            _new_action(type_="none"),  # terminates
        ])
        o.run(s)
        nudge = next(msg for role, msg in s.injected if role == "user")
        assert "curl http://target/login" in nudge

    def test_nudge_only_fires_once_per_attempt(self) -> None:
        """If after the nudge the model emits a tool call, then later
        returns `none` again, we do NOT inject a second nudge — terminates."""
        o, _ = _orch()
        s = StubSolver([
            _new_action(),                      # iter 1: command
            _new_action(type_="none"),          # iter 2: nudge fires
            _new_action(tool_call_id="c3"),     # iter 3: model retries
            _new_action(type_="none"),          # iter 4: no second nudge → exit
        ])
        r = o.run(s)
        assert r.exit_reason == "no_tool_calls"
        assert r.iterations == 4
        nudges = [c for c in s.injected if c[0] == "user"]
        assert len(nudges) == 1


class TestToolErrorFeedback:
    """ when a tool execution raises (e.g. unknown tool name,
    malformed args, handler exception), the orchestrator already returns
    the error string back as the tool result so the model can self-correct.
    These tests pin that contract."""

    def test_unknown_tool_returns_error_to_solver(self) -> None:
        o, tools = _orch()
        tools.execute_tool.side_effect = KeyError("Unknown tool: bogus")
        s = StubSolver([
            _new_action(tool_name="bogus", tool_args={}),
            _new_action(type_="none"),
            _new_action(type_="none"),  # terminates after stuck nudge
        ])
        r = o.run(s)
        # Solver received an error-shaped tool result.
        assert any("ERROR" in (rec.get("output") or "") for rec in s.results_received)
        assert len(r.tool_calls_log) == 1

    def test_handler_exception_returns_error_string(self) -> None:
        o, tools = _orch()
        tools.execute_tool.side_effect = TypeError("missing required arg 'command'")
        s = StubSolver([
            _new_action(tool_args={}),  # malformed → handler raises
            _new_action(type_="none"),
            _new_action(type_="none"),
        ])
        o.run(s)
        recv = s.results_received[0]
        assert "ERROR" in recv["output"]
        assert "missing required arg" in recv["output"]


class TestEventLogger:
    def test_stuck_recovery_event_logged(self) -> None:
        from solkyn.observability.events import EventLogger
        ev = EventLogger()  # in-memory only
        o, _ = _orch(events=ev)
        s = StubSolver([
            _new_action(type_="none"),
            _new_action(type_="none"),
        ])
        o.run(s)
        types = [e["type"] for e in ev._events]
        assert "stuck_recovery_nudge" in types
        nudge_event = next(e for e in ev._events if e["type"] == "stuck_recovery_nudge")
        assert nudge_event["iteration"] == 1
        assert nudge_event["remaining_iterations"] >= 0


class TestSolverActionTypeForIgnoredCases:
    """Sanity: the new branch must be a no-op when the solver returns
    the existing `continue_loop` flag."""

    def test_continue_loop_does_not_trigger_nudge(self) -> None:
        o, _ = _orch()
        s = StubSolver([
            _new_action(type_="none", continue_loop=True),
            _new_action(),                  # real command
            _new_action(type_="none"),      # triggers nudge
            _new_action(type_="none"),      # terminates
        ])
        r = o.run(s)
        assert r.stuck_recovery_used is True
        # Only the post-command `none` triggered the nudge — not the
        # continue_loop one.
        nudges = [c for c in s.injected if c[0] == "user"]
        assert len(nudges) == 1


# Re-export so pytest discovers SolverAction (silence unused-import).
_ = SolverAction
