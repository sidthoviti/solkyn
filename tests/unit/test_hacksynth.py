""" unit tests for :class:`HackSynthSolver`.

Uses a stub LLM that returns canned responses so we exercise:
* planner → command extraction → SolverAction shape,
* handle_result → summariser invocation → rolling-summary append,
* nested-trace shape per ,
* flag-tag short-circuit + malformed-response fallback,
* rolling-summary cap eviction,
* planner view assembly (initial empty, then with summary + last raw turn).
"""

from __future__ import annotations

from typing import Any

import pytest

from solkyn.agents.solvers.base import SolverAction
from solkyn.agents.solvers.hacksynth import HackSynthSolver


class StubLLM:
    """Minimal LLMManager stand-in. Returns scripted responses in order
    and records the messages it was called with."""

    def __init__(self, responses: list[dict[str, Any]]):
        self._responses = list(responses)
        self.calls: list[list[dict[str, Any]]] = []

    def chat(self, messages: list[dict[str, Any]], tools=None, **_kw):  # noqa: ARG002
        self.calls.append(messages)
        if not self._responses:
            raise RuntimeError("StubLLM exhausted")
        resp = self._responses.pop(0)
        # Default usage if not set.
        resp.setdefault("usage", {"input_tokens": 1, "output_tokens": 1})
        return resp


def _make_solver(planner_resps, summarizer_resps=None):
    planner = StubLLM(planner_resps)
    summarizer = StubLLM(summarizer_resps or [])
    s = HackSynthSolver(planner_llm=planner, summarizer_llm=summarizer)
    s.initialize("SYSTEM_BASE")
    s.inject_message("user", "TARGET: http://t — DESC: hack me")
    return s, planner, summarizer


class TestPlannerCommandExtraction:
    def test_command_tag_returns_command_action(self):
        s, planner, _ = _make_solver(
            planner_resps=[{"content": "<reasoning>recon</reasoning>\n<command>curl -sI http://t</command>"}],
        )
        action = s.get_next_action()
        assert isinstance(action, SolverAction)
        assert action.type == "command"
        assert action.tool_name == "bash_exec"
        assert action.tool_args == {"command": "curl -sI http://t"}
        assert action.tool_call_id and action.tool_call_id.startswith("hsh-")
        assert action.reasoning == "recon"
        assert s.get_iteration_count() == 1
        # Planner saw exactly one chat call with system + 2 user msgs.
        assert len(planner.calls) == 1
        call_msgs = planner.calls[0]
        assert call_msgs[0]["role"] == "system"
        assert "HackSynth Planner Mode" in call_msgs[0]["content"]
        assert "SYSTEM_BASE" in call_msgs[0]["content"]
        assert call_msgs[1]["role"] == "user"
        assert "TARGET:" in call_msgs[1]["content"]
        assert call_msgs[2]["role"] == "user"
        assert "Rolling Working Memory" in call_msgs[2]["content"]
        assert "first turn" in call_msgs[2]["content"]

    def test_multiline_command_is_preserved(self):
        s, _, _ = _make_solver(planner_resps=[
            {"content": "<command>\nset -e\ncurl -s http://t/a\ncurl -s http://t/b\n</command>"}
        ])
        action = s.get_next_action()
        assert action.tool_args["command"] == "set -e\ncurl -s http://t/a\ncurl -s http://t/b"

    def test_flag_tag_returns_flag_action(self):
        s, _, _ = _make_solver(planner_resps=[
            {"content": "<reasoning>got it</reasoning>\n<flag>FLAG{abc}</flag>"}
        ])
        action = s.get_next_action()
        assert action.type == "flag"
        assert action.flag == "FLAG{abc}"
        assert action.reasoning == "got it"

    def test_flag_short_circuits_summarizer(self):
        # If planner emits a flag we should NOT call the summarizer at all.
        summarizer = StubLLM([])  # empty — would raise if called
        planner = StubLLM([{"content": "<flag>FLAG{x}</flag>"}])
        s = HackSynthSolver(planner_llm=planner, summarizer_llm=summarizer)
        s.initialize("SYS")
        s.inject_message("user", "u")
        s.get_next_action()
        # No handle_result happens for a flag action — summarizer untouched.
        assert summarizer.calls == []

    def test_malformed_response_returns_none_action(self):
        s, _, _ = _make_solver(planner_resps=[
            {"content": "i don't know what to do"}
        ])
        action = s.get_next_action()
        assert action.type == "none"
        assert action.metadata.get("malformed") is True
        assert action.metadata.get("continue_loop") is False

    def test_flag_text_detection_surfaced_in_metadata(self):
        s, _, _ = _make_solver(planner_resps=[
            {"content": "I see FLAG{deadbeef} in the output\n<command>echo k</command>"}
        ])
        action = s.get_next_action()
        assert action.metadata["flag_in_text"] == "FLAG{deadbeef}"


class TestSummarizerAndRollingMemory:
    def test_handle_result_invokes_summarizer_and_appends_entry(self):
        s, planner, summarizer = _make_solver(
            planner_resps=[
                {"content": "<command>curl -sI http://t</command>"},
                {"content": "<command>curl -sI http://t/admin</command>"},
            ],
            summarizer_resps=[
                {"content": "200 nginx/1.18 — index page only"},
            ],
        )
        action = s.get_next_action()
        s.handle_result(
            {"output": "HTTP/1.1 200 OK\nServer: nginx/1.18\nContent-Length: 612",
             "tool_call_id": action.tool_call_id, "tool_name": "bash_exec"},
        )
        assert len(s._summary_entries) == 1
        assert "nginx/1.18" in s._summary_entries[0]
        # Summariser saw planner reasoning + command + raw output.
        assert len(summarizer.calls) == 1
        sm_user = summarizer.calls[0][1]["content"]
        assert "curl -sI http://t" in sm_user
        assert "nginx/1.18" in sm_user

        # Next planner turn must include the summary + last raw turn in the view.
        s.get_next_action()
        view = planner.calls[1][2]["content"]
        assert "Rolling Working Memory" in view
        assert "1. 200 nginx/1.18" in view
        assert "## Last Turn (raw)" in view
        assert "curl -sI http://t" in view
        assert "Content-Length: 612" in view

    def test_handle_result_without_pending_action_is_noop(self):
        # If orchestrator calls handle_result with no preceding command,
        # we should silently ignore it (not crash, not call summariser).
        s, _, summarizer = _make_solver(
            planner_resps=[],
            summarizer_resps=[],
        )
        s.handle_result({"output": "stray", "tool_call_id": "x", "tool_name": "bash_exec"})
        assert summarizer.calls == []
        assert s._summary_entries == []

    def test_empty_summarizer_response_falls_back_to_stub(self):
        s, _, _ = _make_solver(
            planner_resps=[{"content": "<command>true</command>"}],
            summarizer_resps=[{"content": ""}],
        )
        action = s.get_next_action()
        s.handle_result({"output": "x" * 50, "tool_call_id": action.tool_call_id,
                         "tool_name": "bash_exec"})
        assert len(s._summary_entries) == 1
        assert s._summary_entries[0].startswith("[summary missing]")
        assert "true" in s._summary_entries[0]
        assert "50 chars output" in s._summary_entries[0]

    def test_summary_cap_evicts_oldest(self):
        s = HackSynthSolver(
            planner_llm=StubLLM([]),
            summarizer_llm=StubLLM([]),
            max_summary_chars=20,
        )
        s.initialize("S")
        s.inject_message("user", "u")
        s._summary_entries = ["aaaaaaaa", "bbbbbbbb", "cccccccc"]  # 24 chars
        s._enforce_summary_cap()
        # 16 chars total ≤ 20 cap; oldest gone.
        assert s._summary_entries == ["bbbbbbbb", "cccccccc"]


class TestNestedTraceShape:
    def test_one_full_turn_produces_correct_nested_shape(self):
        """ explicit shape check: turn ⇒ agents=[planner,summarizer]
        ⇒ execution dict with command/output/summary_entry."""
        s, _, _ = _make_solver(
            planner_resps=[{"content": "<reasoning>r</reasoning><command>id</command>"}],
            summarizer_resps=[{"content": "id returned uid=0"}],
        )
        action = s.get_next_action()
        s.handle_result({"output": "uid=0(root)", "tool_call_id": action.tool_call_id,
                         "tool_name": "bash_exec"})
        trace = s.serialize_conversation()
        assert trace["format"] == "nested"
        assert trace["rolling_summary"] == ["id returned uid=0"]
        assert len(trace["turns"]) == 1
        t = trace["turns"][0]
        assert t["turn"] == 1
        names = [a["name"] for a in t["agents"]]
        assert names == ["planner", "summarizer"]
        # Planner agent record carries its messages + raw response + usage.
        assert isinstance(t["agents"][0]["messages"], list)
        assert "<command>id</command>" in t["agents"][0]["response"]
        assert "input_tokens" in t["agents"][0]["usage"]
        # Execution block.
        assert t["execution"] == {
            "command": "id",
            "output": "uid=0(root)",
            "summary_entry": "id returned uid=0",
        }

    def test_flag_action_finalises_turn_without_execution(self):
        s, _, _ = _make_solver(
            planner_resps=[{"content": "<flag>FLAG{x}</flag>"}],
        )
        s.get_next_action()
        trace = s.serialize_conversation()
        assert len(trace["turns"]) == 1
        assert trace["turns"][0]["execution"] is None
        assert [a["name"] for a in trace["turns"][0]["agents"]] == ["planner"]

    def test_two_turns_independent_in_trace(self):
        s, _, _ = _make_solver(
            planner_resps=[
                {"content": "<command>a</command>"},
                {"content": "<command>b</command>"},
            ],
            summarizer_resps=[
                {"content": "ran a"}, {"content": "ran b"},
            ],
        )
        a1 = s.get_next_action()
        s.handle_result({"output": "OUT_A", "tool_call_id": a1.tool_call_id,
                         "tool_name": "bash_exec"})
        a2 = s.get_next_action()
        s.handle_result({"output": "OUT_B", "tool_call_id": a2.tool_call_id,
                         "tool_name": "bash_exec"})
        trace = s.serialize_conversation()
        assert [t["turn"] for t in trace["turns"]] == [1, 2]
        assert trace["turns"][0]["execution"]["output"] == "OUT_A"
        assert trace["turns"][1]["execution"]["output"] == "OUT_B"
        assert trace["rolling_summary"] == ["ran a", "ran b"]


class TestFlatBackCompatView:
    def test_messages_attr_grows_per_turn(self):
        """Legacy code paths read ``solver.messages`` to drain logs.
        We synthesise an interleaved flat view so they keep working."""
        s, _, _ = _make_solver(
            planner_resps=[{"content": "<command>id</command>"}],
            summarizer_resps=[{"content": "uid=0"}],
        )
        # After init: [system, user]
        assert len(s.messages) == 2
        action = s.get_next_action()  # +1 assistant
        assert s.messages[-1]["role"] == "assistant"
        s.handle_result({"output": "uid=0(root)", "tool_call_id": action.tool_call_id,
                         "tool_name": "bash_exec"})
        # +1 tool +1 system summary
        assert s.messages[-2]["role"] == "tool"
        assert s.messages[-2]["content"] == "uid=0(root)"
        assert s.messages[-1]["role"] == "system"
        assert "[summary]" in s.messages[-1]["content"]


class TestSolverAPISurface:
    def test_set_iteration_hint_is_noop(self):
        s, _, _ = _make_solver(planner_resps=[{"content": "<command>ls</command>"}])
        # Should not raise — accepts the call to stay drop-in compatible.
        s.set_iteration_hint(iterations_remaining=10, flag_already_found=False)

    def test_summarizer_defaults_to_planner_when_omitted(self):
        planner = StubLLM([
            {"content": "<command>id</command>"},
            {"content": "uid=0(root) — root shell"},  # used as summarizer call
        ])
        s = HackSynthSolver(planner_llm=planner)
        s.initialize("S")
        s.inject_message("user", "u")
        action = s.get_next_action()
        s.handle_result({"output": "uid=0", "tool_call_id": action.tool_call_id,
                         "tool_name": "bash_exec"})
        # Two calls on the *same* planner LLM (one planner, one summarizer).
        assert len(planner.calls) == 2

    def test_iteration_count_increments_per_planner_call(self):
        s, _, _ = _make_solver(planner_resps=[
            {"content": "<command>a</command>"},
            {"content": "<command>b</command>"},
        ], summarizer_resps=[{"content": "x"}, {"content": "y"}])
        assert s.get_iteration_count() == 0
        a = s.get_next_action()
        assert s.get_iteration_count() == 1
        s.handle_result({"output": "o", "tool_call_id": a.tool_call_id,
                         "tool_name": "bash_exec"})
        # handle_result must NOT increment.
        assert s.get_iteration_count() == 1
        s.get_next_action()
        assert s.get_iteration_count() == 2

    def test_last_llm_usage_reflects_planner(self):
        s, _, _ = _make_solver(planner_resps=[
            {"content": "<command>x</command>",
             "usage": {"input_tokens": 50, "output_tokens": 7}},
        ])
        s.get_next_action()
        assert s.last_llm_usage == {"input_tokens": 50, "output_tokens": 7}


class TestPromptFilesPresent:
    def test_planner_and_summarizer_prompt_files_load(self):
        from solkyn.agents.solvers.hacksynth import (
            _PLANNER_PROMPT_PATH,
            _SUMMARIZER_PROMPT_PATH,
            _load_prompt,
        )
        planner = _load_prompt(_PLANNER_PROMPT_PATH)
        summarizer = _load_prompt(_SUMMARIZER_PROMPT_PATH)
        assert "HackSynth Planner Mode" in planner
        assert "<command>" in planner
        assert "<flag>" in planner
        assert "HackSynth Summarizer" in summarizer
        assert "1–3 line" in summarizer or "1-3 line" in summarizer

    def test_missing_prompt_file_raises(self, tmp_path):
        from solkyn.agents.solvers.hacksynth import HackSynthSolver as HS
        ghost = tmp_path / "ghost.md"
        with pytest.raises(FileNotFoundError):
            HS(planner_llm=StubLLM([]), planner_prompt_path=ghost)
