"""Orchestrator unit tests ( ) — strategy-agnostic loop runner."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from solkyn.agents.flag_detector import FlagDetector
from solkyn.agents.orchestrator import Orchestrator, OrchestratorResult
from solkyn.agents.solvers.base import BaseSolver, SolverAction


class StubSolver(BaseSolver):
    """Returns a fixed sequence of `SolverAction` objects.

    Records every method call for assertion. Owns a `messages` list so
    the orchestrator's drain logic can be exercised.
    """

    def __init__(
        self,
        actions: list[SolverAction],
        messages_per_action: list[list[dict[str, Any]]] | None = None,
        ignore_max: bool = False,
    ) -> None:
        self._actions = list(actions)
        self._msgs_per_action = messages_per_action or []
        self.messages: list[dict[str, Any]] = []
        self.results_received: list[dict[str, Any]] = []
        self.iteration_hints: list[tuple[int, bool]] = []
        self.initialized_with: str | None = None
        self.injected: list[tuple[str, str]] = []
        self._ignore_max = ignore_max

    def initialize(self, system_prompt: str) -> None:
        self.initialized_with = system_prompt
        self.messages.append({"role": "system", "content": system_prompt})

    def get_next_action(self) -> SolverAction:
        if not self._actions:
            return SolverAction(type="none", metadata={"is_new_iteration": True})
        action = self._actions.pop(0)
        # Append any messages that this "LLM call" would have produced.
        idx = len(self.iteration_hints) - 1
        if 0 <= idx < len(self._msgs_per_action):
            self.messages.extend(self._msgs_per_action[idx])
        return action

    def handle_result(self, result: dict[str, Any]) -> None:
        self.results_received.append(result)
        self.messages.append({"role": "tool", "content": result.get("output", "")})

    def serialize_conversation(self) -> dict[str, Any]:
        return {"format": "stub", "messages": self.messages}

    def set_iteration_hint(
        self, iterations_remaining: int, *, flag_already_found: bool = False
    ) -> None:
        self.iteration_hints.append((iterations_remaining, flag_already_found))

    def should_ignore_max_iterations(self) -> bool:
        return self._ignore_max

    def inject_message(self, role: str, content: str) -> None:
        self.injected.append((role, content))
        self.messages.append({"role": role, "content": content})


def _new_action(
    type_: str = "command",
    *,
    is_new_iteration: bool = True,
    flag_in_text: str | None = None,
    continue_loop: bool = False,
    tool_name: str = "bash_exec",
    tool_args: dict | None = None,
    tool_call_id: str = "c1",
    usage: dict | None = None,
) -> SolverAction:
    meta: dict[str, Any] = {"is_new_iteration": is_new_iteration}
    if flag_in_text:
        meta["flag_in_text"] = flag_in_text
    if continue_loop:
        meta["continue_loop"] = True
    if usage is not None:
        meta["usage"] = usage
    if type_ == "command":
        return SolverAction(
            type="command",
            tool_name=tool_name,
            tool_args=tool_args or {"command": "id"},
            tool_call_id=tool_call_id,
            metadata=meta,
        )
    return SolverAction(type="none", metadata=meta)


def _orchestrator(max_iter: int = 5, **kwargs: Any) -> tuple[Orchestrator, MagicMock]:
    tools = MagicMock()
    tools.execute_tool = MagicMock(return_value="some output")
    o = Orchestrator(
        tools=tools,
        flag_detector=FlagDetector(),
        max_iterations=max_iter,
        **kwargs,
    )
    return o, tools


# ---------------------------------------------------------------------------
# Construction + result shape
# ---------------------------------------------------------------------------


class TestResultShape:
    def test_default_result_is_empty(self) -> None:
        r = OrchestratorResult()
        assert r.flags_found == []
        assert r.iterations == 0
        assert r.tool_calls_log == []
        assert r.exit_reason == "no_tool_calls"
        assert r.error is None


# ---------------------------------------------------------------------------
# Termination conditions
# ---------------------------------------------------------------------------


class TestTermination:
    def test_no_tool_calls_terminates_after_one_nudge(self) -> None:
        """ when solver returns `none` with budget remaining,
        orchestrator injects one try-harder nudge then terminates only on
        the SECOND consecutive `none`."""
        o, _ = _orchestrator()
        s = StubSolver([
            _new_action(type_="none"),  # first none → triggers nudge
            _new_action(type_="none"),  # second none → terminates
        ])
        r = o.run(s)
        assert r.exit_reason == "no_tool_calls"
        assert r.iterations == 2
        assert r.stuck_recovery_used is True
        # Exactly one user message was injected by the orchestrator.
        assert len(s.injected) == 1
        assert s.injected[0][0] == "user"
        assert "different approach" in s.injected[0][1].lower()

    def test_no_tool_calls_no_nudge_at_max_iterations(self) -> None:
        """ at max_iterations the cap fires before the nudge can,
        so we exit cleanly without a wasted budget-less LLM call."""
        o, _ = _orchestrator(max_iter=1)
        # Single command consumes the budget, then `none` fires.
        s = StubSolver([
            _new_action(),
            _new_action(type_="none"),
        ])
        r = o.run(s)
        # Iteration cap is checked before solver.get_next_action(), so
        # after iter 1 the second action is never requested.
        assert r.exit_reason == "max_iterations"
        assert r.iterations == 1
        assert r.stuck_recovery_used is False
        assert s.injected == []

    def test_max_iterations_enforced(self) -> None:
        o, _ = _orchestrator(max_iter=2)
        # Three commands + final none — should stop after 2 iters.
        s = StubSolver([
            _new_action(),
            _new_action(tool_call_id="c2"),
            _new_action(tool_call_id="c3"),
        ])
        r = o.run(s)
        assert r.exit_reason == "max_iterations"
        assert r.iterations == 2
        assert len(r.tool_calls_log) == 2

    def test_flag_in_llm_text_terminates_after_iteration(self) -> None:
        o, _ = _orchestrator()
        s = StubSolver([_new_action(type_="none", flag_in_text="FLAG{abcd1234}")])
        r = o.run(s)
        assert r.exit_reason == "flag_found"
        assert r.flags_found == ["FLAG{abcd1234}"]
        assert r.iterations == 1

    def test_flag_in_tool_output_terminates(self) -> None:
        o, tools = _orchestrator()
        tools.execute_tool.return_value = "leaked: FLAG{deadbeef}"
        s = StubSolver([_new_action()])
        r = o.run(s)
        assert r.exit_reason == "flag_found"
        assert r.flags_found == ["FLAG{deadbeef}"]
        assert r.iterations == 1

    def test_continue_loop_metadata_keeps_iterating(self) -> None:
        o, _ = _orchestrator()
        s = StubSolver([
            _new_action(type_="none", continue_loop=True),
            _new_action(type_="none"),                         # triggers nudge
            _new_action(type_="none"),                         # final terminate
        ])
        r = o.run(s)
        assert r.exit_reason == "no_tool_calls"
        # 1 (continue_loop) + 1 (none + nudge) + 1 (final none) = 3
        assert r.iterations == 3
        assert r.stuck_recovery_used is True

    def test_should_ignore_max_iterations_bypasses_cap(self) -> None:
        o, _ = _orchestrator(max_iter=1)
        s = StubSolver(
            [
                _new_action(),
                _new_action(tool_call_id="c2"),
                _new_action(type_="none"),  # triggers nudge
                _new_action(type_="none"),  # final terminate
            ],
            ignore_max=True,
        )
        r = o.run(s)
        # Loop did NOT stop at iteration 1; ran all 4 actions.
        assert r.iterations == 4
        assert r.exit_reason == "no_tool_calls"
        assert r.stuck_recovery_used is True


# ---------------------------------------------------------------------------
# Iteration hint plumbing
# ---------------------------------------------------------------------------


class TestIterationHint:
    def test_hint_passes_remaining_and_flag_status(self) -> None:
        o, tools = _orchestrator(max_iter=3)
        # First call returns benign output, second returns flag.
        tools.execute_tool.side_effect = ["nothing here", "FLAG{deadbeef}"]
        s = StubSolver([
            _new_action(),
            _new_action(tool_call_id="c2"),
        ])
        o.run(s)
        # First hint: 3 iters left, no flag. Second: 2 left, flag NOT yet
        # found at hint time (it'll be found mid-iteration via tool output).
        assert s.iteration_hints[0] == (3, False)
        assert s.iteration_hints[1] == (2, False)


# ---------------------------------------------------------------------------
# Tool dispatch
# ---------------------------------------------------------------------------


class TestToolDispatch:
    def test_command_action_invokes_executor(self) -> None:
        o, tools = _orchestrator()
        s = StubSolver([
            _new_action(tool_args={"command": "ls /tmp"}),
            _new_action(type_="none"),
        ])
        o.run(s)
        tools.execute_tool.assert_called_once_with("bash_exec", {"command": "ls /tmp"})

    def test_command_result_fed_back_to_solver(self) -> None:
        o, tools = _orchestrator()
        tools.execute_tool.return_value = "hello"
        s = StubSolver([
            _new_action(tool_call_id="abc", tool_args={"command": "echo hi"}),
            _new_action(type_="none"),
        ])
        o.run(s)
        assert s.results_received == [{
            "tool_call_id": "abc",
            "tool_name": "bash_exec",
            "tool_args": {"command": "echo hi"},
            "output": "hello",
        }]

    def test_tool_exception_surfaces_as_error_string(self) -> None:
        o, tools = _orchestrator()
        tools.execute_tool.side_effect = RuntimeError("boom")
        s = StubSolver([_new_action(), _new_action(type_="none")])
        o.run(s)
        # The solver received an output starting with "ERROR: boom".
        assert s.results_received[0]["output"].startswith("ERROR: boom")

    def test_tool_log_entries_recorded(self) -> None:
        o, _ = _orchestrator()
        s = StubSolver([
            _new_action(tool_call_id="c1", tool_args={"command": "id"}),
            _new_action(tool_call_id="c2", tool_args={"command": "ls"}),
            _new_action(type_="none"),
        ])
        r = o.run(s)
        assert len(r.tool_calls_log) == 2
        assert r.tool_calls_log[0]["tool"] == "bash_exec"
        assert r.tool_calls_log[0]["args"] == {"command": "id"}
        assert "duration" in r.tool_calls_log[0]


# ---------------------------------------------------------------------------
# Batched tool calls (is_new_iteration semantics)
# ---------------------------------------------------------------------------


class TestBatching:
    def test_drained_actions_dont_increment_iterations(self) -> None:
        o, _ = _orchestrator()
        s = StubSolver([
            _new_action(tool_call_id="a", is_new_iteration=True),
            _new_action(tool_call_id="b", is_new_iteration=False),  # batch sibling
            _new_action(tool_call_id="c", is_new_iteration=False),  # batch sibling
            _new_action(type_="none"),  # triggers  nudge
            _new_action(type_="none"),  # final terminate
        ])
        r = o.run(s)
        # 3 tool calls but only 3 LLM iterations (1 batched + 1 nudge + 1 terminate).
        assert r.iterations == 3
        assert len(r.tool_calls_log) == 3


# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------


class TestStatePersistence:
    def test_state_save_called_per_iteration(self, tmp_path: Any) -> None:
        from solkyn.agents.state import ScanState

        o, _ = _orchestrator()
        s = StubSolver([
            _new_action(tool_call_id="a"),
            _new_action(tool_call_id="b"),
            _new_action(type_="none"),
        ])
        s.initialize("sys")
        s.inject_message("user", "u")
        state = ScanState(
            scan_id="t", target_url="http://x", description="d", max_iterations=5,
        )
        scan_dir = str(tmp_path / "scan")
        o.run(s, scan_dir=scan_dir, state=state)
        # State file written.
        import json
        with open(f"{scan_dir}/state.json") as f:
            data = json.load(f)
        assert data["iterations"] >= 2

    def test_state_log_appends_messages(self, tmp_path: Any) -> None:
        from solkyn.agents.state import ScanState

        o, _ = _orchestrator()
        s = StubSolver([_new_action(type_="none")])
        s.initialize("sys")
        s.inject_message("user", "u")
        state = ScanState(
            scan_id="t", target_url="http://x", description="d", max_iterations=5,
        )
        scan_dir = str(tmp_path / "scan")
        o.run(s, scan_dir=scan_dir, state=state)
        # logs/solver.jsonl exists with at least the system + user seed.
        from pathlib import Path
        log_lines = Path(scan_dir, "logs", "solver.jsonl").read_text().strip().splitlines()
        assert len(log_lines) >= 2

    def test_no_state_no_dir_runs_clean(self) -> None:
        o, _ = _orchestrator()
        s = StubSolver([
            _new_action(),
            _new_action(type_="none"),  # triggers nudge
            _new_action(type_="none"),  # terminate
        ])
        r = o.run(s)  # no scan_dir / state
        assert r.iterations == 3


# ---------------------------------------------------------------------------
# Display + event hooks
# ---------------------------------------------------------------------------


class TestObservability:
    def test_display_iteration_start_called_per_iteration(self) -> None:
        display = MagicMock()
        o, _ = _orchestrator(display=display)
        s = StubSolver([
            _new_action(tool_call_id="a"),
            _new_action(type_="none"),  # nudge
            _new_action(type_="none"),  # terminate
        ])
        o.run(s)
        assert display.iteration_start.call_count == 3

    def test_display_flag_found_called_on_text_flag(self) -> None:
        display = MagicMock()
        o, _ = _orchestrator(display=display)
        s = StubSolver([_new_action(type_="none", flag_in_text="FLAG{abcd1234}")])
        o.run(s)
        display.flag_found.assert_called_once_with("FLAG{abcd1234}", 1)

    def test_event_logger_records_llm_and_tool_calls(self) -> None:
        events = MagicMock()
        o, _ = _orchestrator(events=events)
        s = StubSolver([
            _new_action(usage={"input_tokens": 10, "output_tokens": 5}),
            _new_action(type_="none"),  # nudge
            _new_action(type_="none"),  # terminate
        ])
        o.run(s)
        assert events.iteration_start.call_count == 3
        assert events.llm_call.call_count == 3
        assert events.tool_call.call_count == 1


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    def test_solver_exception_caught_and_surfaced(self) -> None:
        o, _ = _orchestrator()

        class ExplodingSolver(StubSolver):
            def get_next_action(self) -> SolverAction:
                raise ValueError("solver kaboom")

        s = ExplodingSolver([_new_action()])
        r = o.run(s)
        assert r.exit_reason == "error"
        assert r.error == "solver kaboom"


# ---------------------------------------------------------------------------
# Phase 7 P0.5 — flag-detected nudge
# ---------------------------------------------------------------------------


class TestFlagDetectedNudge:
    """When the orchestrator's flag detector finds a flag in tool output,
    it should inject a strong user message telling the solver to call
    end_task immediately. This recovers challenges where the agent's own
    parsing missed/mangled the flag."""

    def test_nudge_injected_when_tool_output_contains_flag(self) -> None:
        o, tools = _orchestrator()
        tools.execute_tool = MagicMock(
            return_value="leaked: flag{85c0d827-5e28-4577-be2b-319bdcbf872d}"
        )
        s = StubSolver([
            _new_action(),                                  # iter 1: tool call
            _new_action(type_="none"),                      # iter 2: terminate
        ])
        o.run(s)
        # A user-role nudge with the detected flag should have been injected.
        flag_nudges = [
            content for role, content in s.injected
            if role == "user" and "FLAG AUTO-DETECTED" in content
        ]
        assert len(flag_nudges) == 1
        assert "flag{85c0d827-5e28-4577-be2b-319bdcbf872d}" in flag_nudges[0]
        assert "end_task" in flag_nudges[0]

    def test_no_nudge_when_no_flag(self) -> None:
        o, tools = _orchestrator()
        tools.execute_tool = MagicMock(return_value="boring output")
        s = StubSolver([
            _new_action(),
            _new_action(type_="none"),
        ])
        o.run(s)
        flag_nudges = [
            content for role, content in s.injected
            if "FLAG AUTO-DETECTED" in content
        ]
        assert flag_nudges == []

    def test_inject_failure_does_not_abort_run(self) -> None:
        """If a solver's inject_message blows up, the orchestrator must
        keep running — the nudge is best-effort."""
        o, tools = _orchestrator()
        tools.execute_tool = MagicMock(return_value="found: flag{abcd-1234}")

        class BrokenInjectSolver(StubSolver):
            def inject_message(self, role: str, content: str) -> None:
                raise RuntimeError("inject broke")

        s = BrokenInjectSolver([
            _new_action(),
            _new_action(type_="none"),
        ])
        r = o.run(s)
        # Run should still complete cleanly, with the flag in the result.
        assert "flag{abcd-1234}" in r.flags_found


# ---------------------------------------------------------------------------
# SolverAgent integration shim still wires Orchestrator
# ---------------------------------------------------------------------------


class TestSolverAgentShim:
    def test_solver_agent_uses_orchestrator(self) -> None:
        import inspect

        from solkyn.agents.solver import SolverAgent

        src = inspect.getsource(SolverAgent.run)
        assert "Orchestrator(" in src
        assert "orchestrator.run(" in src


# ===========================================================================
#  Deadline + CostTracker orchestrator integration
# ===========================================================================


class TestDeadlineLimit:
    def test_expired_deadline_exits_with_time_limit(self) -> None:
        from solkyn.core.deadline import Deadline
        d = Deadline(max_seconds=0.001)
        import time as _t
        _t.sleep(0.01)
        o, _ = _orchestrator(deadline=d)
        s = StubSolver([_new_action(), _new_action(type_="none")])
        r = o.run(s)
        assert r.exit_reason == "time_limit"
        assert r.iterations == 0  # never advanced past the gate

    def test_unbounded_deadline_does_not_block(self) -> None:
        from solkyn.core.deadline import Deadline
        o, _ = _orchestrator(deadline=Deadline(max_seconds=None))
        s = StubSolver([
            _new_action(),
            _new_action(type_="none"),  # nudge
            _new_action(type_="none"),  # terminate
        ])
        r = o.run(s)
        assert r.exit_reason == "no_tool_calls"
        assert r.iterations == 3


class TestCostLimit:
    def test_over_budget_exits_with_cost_limit(self) -> None:
        from solkyn.core.cost import CostTracker, ModelPrice
        ct = CostTracker(prices={"m": ModelPrice(input_per_1k=1.0)})
        ct.record("m", {"input_tokens": 1000})  # $1.00
        o, _ = _orchestrator(
            cost_tracker=ct, max_cost_usd=0.50, model_name="m",
        )
        s = StubSolver([_new_action(), _new_action(type_="none")])
        r = o.run(s)
        assert r.exit_reason == "cost_limit"
        assert r.iterations == 0

    def test_cost_records_per_iteration(self) -> None:
        from solkyn.core.cost import CostTracker, ModelPrice
        ct = CostTracker(prices={"m": ModelPrice(input_per_1k=0.01, output_per_1k=0.02)})
        o, _ = _orchestrator(
            max_iter=10, cost_tracker=ct, max_cost_usd=None, model_name="m",
        )
        s = StubSolver([
            _new_action(usage={"input_tokens": 100, "output_tokens": 50}),
            _new_action(type_="none", usage={"input_tokens": 100, "output_tokens": 50}),
        ])
        o.run(s)
        # 2 iterations × ($0.001 + $0.001) = $0.004
        assert ct.total_usd == pytest.approx(0.004)

    def test_no_tracker_no_recording(self) -> None:
        # Default _orchestrator() sets neither — should run cleanly without
        # cost gates firing.
        o, _ = _orchestrator()
        s = StubSolver([_new_action(), _new_action(type_="none")])
        r = o.run(s)
        assert r.exit_reason == "no_tool_calls"


class TestExitReasonPrecedence:
    def test_time_limit_beats_cost_limit(self) -> None:
        import time as _t

        from solkyn.core.cost import CostTracker, ModelPrice
        from solkyn.core.deadline import Deadline

        d = Deadline(max_seconds=0.001)
        _t.sleep(0.01)
        ct = CostTracker(prices={"m": ModelPrice(input_per_1k=1.0)})
        ct.record("m", {"input_tokens": 1000})  # over budget too
        o, _ = _orchestrator(
            deadline=d, cost_tracker=ct, max_cost_usd=0.5, model_name="m",
        )
        s = StubSolver([_new_action(type_="none")])
        r = o.run(s)
        assert r.exit_reason == "time_limit"


# ===========================================================================
#  Stagnation detection + tactic-change nudge
# ===========================================================================


class TestStagnationNudge:
    """Orchestrator should inject a tactic-change nudge when the solver
    repeatedly runs the same command or gets the same response."""

    def test_repeated_command_triggers_nudge(self) -> None:
        o, tools = _orchestrator(max_iter=10)
        # Each tool call returns a unique result (so command repetition is
        # the only signal), but the agent runs the same command 3 times.
        outputs = iter(["A" * 100, "B" * 200, "C" * 300, ""])
        tools.execute_tool = MagicMock(side_effect=lambda *_a, **_k: next(outputs))
        same_args = {"command": "ls /tmp"}
        s = StubSolver([
            _new_action(tool_args=same_args, tool_call_id="c1"),
            _new_action(tool_args=same_args, tool_call_id="c2"),
            _new_action(tool_args=same_args, tool_call_id="c3"),
            _new_action(type_="none"),
        ])
        r = o.run(s)
        nudges = [c for role, c in s.injected if "STAGNATION" in c]
        assert len(nudges) == 1
        assert "ls /tmp" in nudges[0]
        assert r.stagnation_nudges_used == 1

    def test_repeated_result_triggers_nudge(self) -> None:
        o, tools = _orchestrator(max_iter=10)
        # 3 different commands, but the target keeps returning the same body.
        tools.execute_tool = MagicMock(return_value="HTTP/1.1 404 Not Found\r\n\r\n")
        s = StubSolver([
            _new_action(tool_args={"command": "curl /a"}, tool_call_id="c1"),
            _new_action(tool_args={"command": "curl /b"}, tool_call_id="c2"),
            _new_action(tool_args={"command": "curl /c"}, tool_call_id="c3"),
            _new_action(type_="none"),
        ])
        r = o.run(s)
        nudges = [c for role, c in s.injected if "STAGNATION" in c]
        assert len(nudges) == 1
        assert "same response" in nudges[0]
        assert r.stagnation_nudges_used == 1

    def test_no_nudge_when_commands_differ_and_results_differ(self) -> None:
        o, tools = _orchestrator(max_iter=10)
        outs = iter(["resp_a" + "x" * 50, "resp_b" + "y" * 60, "resp_c" + "z" * 70, ""])
        tools.execute_tool = MagicMock(side_effect=lambda *_a, **_k: next(outs))
        s = StubSolver([
            _new_action(tool_args={"command": "ls /a"}, tool_call_id="c1"),
            _new_action(tool_args={"command": "ls /b"}, tool_call_id="c2"),
            _new_action(tool_args={"command": "ls /c"}, tool_call_id="c3"),
            _new_action(type_="none"),
        ])
        r = o.run(s)
        nudges = [c for role, c in s.injected if "STAGNATION" in c]
        assert nudges == []
        assert r.stagnation_nudges_used == 0

    def test_nudge_capped_at_max(self) -> None:
        o, tools = _orchestrator(max_iter=20)
        same_args = {"command": "id"}
        tools.execute_tool = MagicMock(return_value="uid=0(root)")
        # 9 identical calls — should fire 2 nudges (cap), not 9.
        actions = [
            _new_action(tool_args=same_args, tool_call_id=f"c{i}")
            for i in range(9)
        ] + [_new_action(type_="none")]
        s = StubSolver(actions)
        r = o.run(s)
        nudges = [c for role, c in s.injected if "STAGNATION" in c]
        assert len(nudges) == 2
        assert r.stagnation_nudges_used == 2

    def test_inject_failure_does_not_abort(self) -> None:
        class BrokenInjectSolver(StubSolver):
            def inject_message(self, role: str, content: str) -> None:
                if "STAGNATION" in content:
                    raise RuntimeError("inject broke")
                super().inject_message(role, content)

        o, tools = _orchestrator(max_iter=10)
        same_args = {"command": "id"}
        tools.execute_tool = MagicMock(return_value="ok")
        s = BrokenInjectSolver([
            _new_action(tool_args=same_args, tool_call_id="c1"),
            _new_action(tool_args=same_args, tool_call_id="c2"),
            _new_action(tool_args=same_args, tool_call_id="c3"),
            _new_action(type_="none"),
        ])
        r = o.run(s)
        # nudge_used counter NOT incremented on failure (stays at 0).
        assert r.stagnation_nudges_used == 0
        # And the run completed cleanly.
        assert r.exit_reason == "no_tool_calls"
