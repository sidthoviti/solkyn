"""Tests for solkyn.agents.solvers.base — BaseSolver ABC + SolverAction."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from solkyn.agents.solvers import BaseSolver, SolverAction

# ---------------------------------------------------------------------------
# SolverAction
# ---------------------------------------------------------------------------


class TestSolverAction:
    def test_command_action_with_command_string(self) -> None:
        a = SolverAction(type="command", command="ls -la", reasoning="recon")
        assert a.type == "command"
        assert a.command == "ls -la"
        assert a.reasoning == "recon"

    def test_command_action_with_tool_call(self) -> None:
        a = SolverAction(
            type="command",
            tool_name="bash_exec",
            tool_args={"command": "id"},
            tool_call_id="call_1",
        )
        assert a.tool_name == "bash_exec"
        assert a.tool_args == {"command": "id"}
        assert a.tool_call_id == "call_1"

    def test_flag_action(self) -> None:
        a = SolverAction(type="flag", flag="FLAG{abc123}")
        assert a.flag == "FLAG{abc123}"

    def test_none_action(self) -> None:
        a = SolverAction(type="none", reasoning="model gave up")
        assert a.type == "none"
        assert a.command is None
        assert a.flag is None

    def test_command_without_command_or_tool_raises(self) -> None:
        with pytest.raises(ValidationError):
            SolverAction(type="command")

    def test_flag_without_flag_raises(self) -> None:
        with pytest.raises(ValidationError):
            SolverAction(type="flag")

    def test_flag_with_empty_string_raises(self) -> None:
        with pytest.raises(ValidationError):
            SolverAction(type="flag", flag="")

    def test_invalid_type_raises(self) -> None:
        with pytest.raises(ValidationError):
            SolverAction(type="explode")  # type: ignore[arg-type]

    def test_round_trip_json(self) -> None:
        original = SolverAction(
            type="command",
            command="curl http://x",
            reasoning="probe target",
            tool_name="bash_exec",
            tool_args={"command": "curl http://x"},
            tool_call_id="call_42",
            metadata={"turn": 3},
        )
        as_json = original.model_dump_json()
        restored = SolverAction.model_validate_json(as_json)
        assert restored == original

    def test_dict_round_trip(self) -> None:
        a = SolverAction(type="flag", flag="FLAG{x}", metadata={"source": "tool_output"})
        d = a.model_dump()
        # Pydantic dump must be JSON-serialisable for trace persistence.
        assert json.dumps(d)
        restored = SolverAction.model_validate(d)
        assert restored == a


# ---------------------------------------------------------------------------
# BaseSolver ABC
# ---------------------------------------------------------------------------


class TestBaseSolverContract:
    def test_cannot_instantiate_abstract(self) -> None:
        with pytest.raises(TypeError):
            BaseSolver()  # type: ignore[abstract]

    def test_partial_implementation_still_abstract(self) -> None:
        class Half(BaseSolver):
            def initialize(self, system_prompt: str) -> None:
                pass

            def get_next_action(self) -> SolverAction:
                return SolverAction(type="none")

            # Missing handle_result + serialize_conversation.

        with pytest.raises(TypeError):
            Half()  # type: ignore[abstract]

    def test_full_implementation_instantiates(self) -> None:
        class Full(BaseSolver):
            def __init__(self) -> None:
                self.messages: list[dict] = []

            def initialize(self, system_prompt: str) -> None:
                self.messages.append({"role": "system", "content": system_prompt})

            def get_next_action(self) -> SolverAction:
                return SolverAction(type="none", reasoning="test")

            def handle_result(self, result: dict) -> None:
                self.messages.append({"role": "tool", "content": str(result)})

            def serialize_conversation(self) -> dict:
                return {"format": "flat", "messages": self.messages}

        s = Full()
        s.initialize("you are a test agent")
        s.handle_result({"stdout": "ok", "exit_code": 0})
        action = s.get_next_action()
        assert action.type == "none"
        trace = s.serialize_conversation()
        assert trace["format"] == "flat"
        assert len(trace["messages"]) == 2

    def test_default_should_ignore_max_iterations_is_false(self) -> None:
        class Min(BaseSolver):
            def initialize(self, system_prompt: str) -> None:
                pass

            def get_next_action(self) -> SolverAction:
                return SolverAction(type="none")

            def handle_result(self, result: dict) -> None:
                pass

            def serialize_conversation(self) -> dict:
                return {"format": "flat", "messages": []}

        assert Min().should_ignore_max_iterations() is False

    def test_default_solver_prompt_file_is_none(self) -> None:
        class Min(BaseSolver):
            def initialize(self, system_prompt: str) -> None:
                pass

            def get_next_action(self) -> SolverAction:
                return SolverAction(type="none")

            def handle_result(self, result: dict) -> None:
                pass

            def serialize_conversation(self) -> dict:
                return {"format": "flat", "messages": []}

        assert Min().get_solver_prompt_file() is None

    def test_inject_message_default_is_noop(self) -> None:
        class Min(BaseSolver):
            def initialize(self, system_prompt: str) -> None:
                pass

            def get_next_action(self) -> SolverAction:
                return SolverAction(type="none")

            def handle_result(self, result: dict) -> None:
                pass

            def serialize_conversation(self) -> dict:
                return {"format": "flat", "messages": []}

        # Should not raise.
        Min().inject_message("user", "try harder")

    def test_default_iteration_count_is_zero(self) -> None:
        class Min(BaseSolver):
            def initialize(self, system_prompt: str) -> None:
                pass

            def get_next_action(self) -> SolverAction:
                return SolverAction(type="none")

            def handle_result(self, result: dict) -> None:
                pass

            def serialize_conversation(self) -> dict:
                return {"format": "flat", "messages": []}

        assert Min().get_iteration_count() == 0
