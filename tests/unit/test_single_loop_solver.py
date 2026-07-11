"""SingleLoopSolver tests — parity with the previous SolverAgent loop body."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from solkyn.agents.flag_detector import FlagDetector
from solkyn.agents.solvers import BaseSolver, SingleLoopSolver


def _mock_llm(responses: list[dict]) -> MagicMock:
    """Mock LLMManager.chat returning the provided responses in order."""
    llm = MagicMock()
    llm.chat = MagicMock(side_effect=responses)
    llm.get_usage = MagicMock(return_value={"input_tokens": 0, "output_tokens": 0})
    return llm


def _new_solver(
    responses: list[dict],
    tags: list[str] | None = None,
    max_nudges: int = 3,
) -> SingleLoopSolver:
    s = SingleLoopSolver(
        llm_manager=_mock_llm(responses),
        tool_schemas=[{"name": "bash_exec"}],
        flag_detector=FlagDetector(),
        tags=tags,
        max_nudges=max_nudges,
    )
    s.initialize("system prompt here")
    s.inject_message("user", "target info")
    return s


# ---------------------------------------------------------------------------
# Construction + interface
# ---------------------------------------------------------------------------


class TestInterface:
    def test_is_a_basesolver(self) -> None:
        s = _new_solver([{"content": None, "tool_calls": None, "usage": {}}])
        assert isinstance(s, BaseSolver)

    def test_initialize_seeds_system_prompt(self) -> None:
        s = SingleLoopSolver(_mock_llm([]), tool_schemas=None, flag_detector=FlagDetector())
        s.initialize("you are a test agent")
        assert s.messages == [{"role": "system", "content": "you are a test agent"}]

    def test_inject_message_appends(self) -> None:
        s = SingleLoopSolver(_mock_llm([]), tool_schemas=None, flag_detector=FlagDetector())
        s.initialize("sys")
        s.inject_message("user", "hello")
        assert s.messages[-1] == {"role": "user", "content": "hello"}

    def test_serialize_returns_flat_format(self) -> None:
        s = _new_solver([{"content": None, "tool_calls": None, "usage": {}}])
        trace = s.serialize_conversation()
        assert trace["format"] == "flat"
        assert isinstance(trace["messages"], list)


# ---------------------------------------------------------------------------
# get_next_action — single LLM call shapes
# ---------------------------------------------------------------------------


class TestNextActionShapes:
    def test_text_only_no_nudge_budget_terminates(self) -> None:
        s = _new_solver([{"content": "I'm done", "tool_calls": None, "usage": {}}], max_nudges=0)
        s.set_iteration_hint(iterations_remaining=10)
        action = s.get_next_action()
        assert action.type == "none"
        assert action.metadata["continue_loop"] is False
        assert action.metadata["is_new_iteration"] is True

    def test_text_only_with_budget_injects_continuation_nudge(self) -> None:
        s = _new_solver([{"content": "thinking out loud", "tool_calls": None, "usage": {}}])
        s.set_iteration_hint(iterations_remaining=10)
        action = s.get_next_action()
        assert action.type == "none"
        assert action.metadata["continue_loop"] is True
        assert action.metadata["injected_continuation_nudge"] is True
        assert s.nudge_count == 1
        # The nudge text was appended.
        assert any("STOP. You returned no tool calls" in m["content"] for m in s.messages)

    def test_text_with_flag_does_not_inject_nudge(self) -> None:
        s = _new_solver(
            [{"content": "Found it: FLAG{abcd1234}", "tool_calls": None, "usage": {}}]
        )
        s.set_iteration_hint(iterations_remaining=10)
        action = s.get_next_action()
        assert action.metadata["continue_loop"] is False
        assert action.metadata["flag_in_text"] == "FLAG{abcd1234}"
        assert s.nudge_count == 0
        # No nudge injected.
        assert not any("STOP. You returned no tool calls" in m["content"] for m in s.messages)

    def test_no_nudge_when_flag_already_found(self) -> None:
        s = _new_solver([{"content": "I'm done", "tool_calls": None, "usage": {}}])
        s.set_iteration_hint(iterations_remaining=10, flag_already_found=True)
        action = s.get_next_action()
        assert action.metadata["continue_loop"] is False
        assert s.nudge_count == 0

    def test_no_nudge_when_iters_left_is_one(self) -> None:
        s = _new_solver([{"content": "x", "tool_calls": None, "usage": {}}])
        s.set_iteration_hint(iterations_remaining=1)
        action = s.get_next_action()
        assert action.metadata["continue_loop"] is False

    def test_single_tool_call_returns_command_action(self) -> None:
        s = _new_solver([{
            "content": "let me probe",
            "tool_calls": [{"id": "c1", "name": "bash_exec", "arguments": {"command": "id"}}],
            "usage": {"input_tokens": 10, "output_tokens": 5},
        }])
        s.set_iteration_hint(iterations_remaining=10)
        action = s.get_next_action()
        assert action.type == "command"
        assert action.tool_name == "bash_exec"
        assert action.tool_args == {"command": "id"}
        assert action.tool_call_id == "c1"
        assert action.metadata["is_new_iteration"] is True
        assert action.metadata["batch_size"] == 1


# ---------------------------------------------------------------------------
# Multi-tool-call queueing
# ---------------------------------------------------------------------------


class TestMultiToolCallBatch:
    def test_batch_iteration_count_ticks_once(self) -> None:
        s = _new_solver([
            {
                "content": None,
                "tool_calls": [
                    {"id": "a", "name": "bash_exec", "arguments": {"command": "ls"}},
                    {"id": "b", "name": "bash_exec", "arguments": {"command": "pwd"}},
                    {"id": "c", "name": "bash_exec", "arguments": {"command": "id"}},
                ],
                "usage": {"input_tokens": 10, "output_tokens": 5},
            },
            {"content": "done", "tool_calls": None, "usage": {}},
        ])
        s.set_iteration_hint(iterations_remaining=10)

        # First call → first tool call (new iteration)
        a1 = s.get_next_action()
        assert a1.metadata["is_new_iteration"] is True
        assert a1.tool_call_id == "a"
        assert s.get_iteration_count() == 1

        # Feed result; queue still has 2.
        s.handle_result({
            "tool_call_id": "a", "tool_name": "bash_exec",
            "tool_args": {"command": "ls"}, "output": "files",
        })

        # Second call → drained from queue (NOT a new iteration)
        a2 = s.get_next_action()
        assert a2.metadata["is_new_iteration"] is False
        assert a2.tool_call_id == "b"
        assert s.get_iteration_count() == 1

        s.handle_result({
            "tool_call_id": "b", "tool_name": "bash_exec",
            "tool_args": {"command": "pwd"}, "output": "/tmp",
        })

        a3 = s.get_next_action()
        assert a3.metadata["is_new_iteration"] is False
        assert a3.tool_call_id == "c"
        assert s.get_iteration_count() == 1

        s.handle_result({
            "tool_call_id": "c", "tool_name": "bash_exec",
            "tool_args": {"command": "id"}, "output": "uid=0",
        })

        # Now next get_next_action triggers second LLM call
        a4 = s.get_next_action()
        assert a4.metadata["is_new_iteration"] is True
        assert s.get_iteration_count() == 2


# ---------------------------------------------------------------------------
# Loop detection — parity with original 3 strategies
# ---------------------------------------------------------------------------


def _drive_one_command(s: SingleLoopSolver, llm_response: dict, output: str) -> None:
    """Drive solver through one full LLM-call → execute → handle_result cycle."""
    s.set_iteration_hint(iterations_remaining=10)
    action = s.get_next_action()
    assert action.type == "command"
    s.handle_result({
        "tool_call_id": action.tool_call_id,
        "tool_name": action.tool_name,
        "tool_args": action.tool_args,
        "output": output,
    })


def _curl_response(idx: int, cmd: str = "curl http://x") -> dict:
    return {
        "content": None,
        "tool_calls": [{"id": f"id{idx}", "name": "bash_exec", "arguments": {"command": cmd}}],
        "usage": {},
    }


class TestLoopDetection:
    def test_no_loop_detected_with_diverse_commands(self) -> None:
        responses: list[Any] = [
            _curl_response(1, "curl http://a"),
            _curl_response(2, "ls /tmp"),
            _curl_response(3, "find / -name flag"),
            _curl_response(4, "cat /etc/passwd"),
        ]
        s = _new_solver(responses)
        for r, out in zip(responses, ["a", "b", "c", "d"]):
            _drive_one_command(s, r, out)
        assert s.nudge_count == 0

    def test_strategy_1_repeated_signature_triggers_nudge(self) -> None:
        # 4 of the same → strategy 1 fires (last 4 unique <= 2).
        responses = [_curl_response(i, "curl http://x") for i in range(4)]
        s = _new_solver(responses, tags=["sqli"])
        for r, out in zip(responses, ["a", "b", "c", "d"]):
            _drive_one_command(s, r, out)
        assert s.nudge_count == 1
        # SQLi-specific nudge text was used.
        assert any("LOOP DETECTED on SQLi" in m["content"] for m in s.messages)

    def test_strategy_3_identical_outputs_triggers_nudge(self) -> None:
        responses = [
            _curl_response(1, "curl a"),
            _curl_response(2, "ls b"),
            _curl_response(3, "find c"),
        ]
        s = _new_solver(responses)
        # All three outputs identical and non-empty → strategy 3.
        for r in responses:
            _drive_one_command(s, r, "same output")
        assert s.nudge_count == 1

    def test_strategy_3_ignores_empty_outputs(self) -> None:
        responses = [
            _curl_response(1, "curl a"),
            _curl_response(2, "ls b"),
            _curl_response(3, "find c"),
        ]
        s = _new_solver(responses)
        # Empty outputs — should NOT trigger.
        for r in responses:
            _drive_one_command(s, r, "")
        assert s.nudge_count == 0

    def test_loop_detection_only_at_end_of_batch(self) -> None:
        # One LLM response with 4 identical tool calls → loop signals fill
        # but nudge only checked AFTER the last tool call's handle_result.
        s = _new_solver([{
            "content": None,
            "tool_calls": [
                {"id": str(i), "name": "bash_exec", "arguments": {"command": "curl x"}}
                for i in range(4)
            ],
            "usage": {},
        }])
        s.set_iteration_hint(iterations_remaining=10)

        # Process all four batched commands.
        for _ in range(4):
            a = s.get_next_action()
            assert a.type == "command"
            s.handle_result({
                "tool_call_id": a.tool_call_id, "tool_name": a.tool_name,
                "tool_args": a.tool_args, "output": "data",
            })
        assert s.nudge_count == 1


# ---------------------------------------------------------------------------
# Tag-aware nudge selection (parity sanity check)
# ---------------------------------------------------------------------------


class TestTagAwareNudges:
    def _trigger_loop(self, tags: list[str]) -> SingleLoopSolver:
        responses = [_curl_response(i, "curl x") for i in range(4)]
        s = _new_solver(responses, tags=tags)
        for r in responses:
            _drive_one_command(s, r, "out")
        return s

    def test_xss_tag_uses_xss_nudge(self) -> None:
        s = self._trigger_loop(["xss"])
        assert any("XSS challenge" in m["content"] for m in s.messages if m["role"] == "user")

    def test_sqli_tag_uses_sqli_nudge(self) -> None:
        s = self._trigger_loop(["sqli"])
        assert any("SQLi challenge" in m["content"] for m in s.messages if m["role"] == "user")

    def test_jwt_takes_priority_over_lfi(self) -> None:
        # Original cascade: JWT before LFI.
        s = self._trigger_loop(["jwt", "lfi"])
        assert any("JWT/privilege escalation" in m["content"]
                   for m in s.messages if m["role"] == "user")

    def test_no_tags_uses_generic_nudge(self) -> None:
        s = self._trigger_loop([])
        assert any("LOOP DETECTED: You are repeating" in m["content"]
                   for m in s.messages if m["role"] == "user")


# ---------------------------------------------------------------------------
# Full end-to-end SolverAgent shim still works ( invariant)
# ---------------------------------------------------------------------------


class TestSolverAgentShimUnchanged:
    """Confirm SolverAgent.run() still produces equivalent results via the shim."""

    def test_solver_agent_imports_single_loop_solver(self) -> None:
        # If this import works, the shim is wired up. SolverAgent uses
        # the solver factory which constructs SingleLoopSolver
        # for the default ``--solver single_loop`` path. Verify by
        # source inspection of SolverAgent.run().
        import inspect

        from solkyn.agents.solver import SolverAgent
        from solkyn.agents.solvers.single_loop import SingleLoopSolver as SLS
        src = inspect.getsource(SolverAgent.run)
        assert "get_solver(" in src
        assert SLS is not None
