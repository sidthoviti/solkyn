""" tests for the nested conversation format + report rendering.

Covers:
* ``write_conversation_json`` accepts both legacy ``list[dict]`` and
  the new trace ``dict`` (flat or nested).
* Round-trip: ``serialize_conversation()`` → ``write_conversation_json``
  → ``json.loads`` produces the same shape.
* ``generate_report`` renders nested traces via collapsible per-agent
  blocks plus per-turn execution.
"""

from __future__ import annotations

import json
from pathlib import Path

from solkyn.agents.attempt_dir import write_conversation_json
from solkyn.agents.solvers.single_loop import SingleLoopSolver
from solkyn.reporting.report_generator import generate_report


class TestWriteConversationJsonAcceptsBothShapes:
    def test_list_input_wraps_into_flat(self, tmp_path):
        msgs = [{"role": "system", "content": "S"},
                {"role": "user", "content": "U"}]
        path = write_conversation_json(tmp_path, msgs)
        data = json.loads(path.read_text())
        assert data == {"format": "flat", "messages": msgs}

    def test_dict_flat_passthrough(self, tmp_path):
        trace = {"format": "flat", "messages": [{"role": "system", "content": "S"}]}
        path = write_conversation_json(tmp_path, trace)
        data = json.loads(path.read_text())
        assert data == trace

    def test_dict_nested_passthrough(self, tmp_path):
        trace = {
            "format": "nested",
            "turns": [
                {"turn": 1,
                 "agents": [{"name": "planner", "messages": [], "response": "<command>id</command>",
                             "usage": {"input_tokens": 1, "output_tokens": 2}},
                            {"name": "summarizer", "messages": [], "response": "uid=0",
                             "usage": {"input_tokens": 3, "output_tokens": 1}}],
                 "execution": {"command": "id", "output": "uid=0(root)",
                               "summary_entry": "uid=0"}},
            ],
            "rolling_summary": ["uid=0"],
        }
        path = write_conversation_json(tmp_path, trace)
        data = json.loads(path.read_text())
        assert data == trace


class TestRoundTripBothFormats:
    def test_flat_roundtrip_via_singleloop_serialize(self, tmp_path):
        # SingleLoopSolver.serialize_conversation() → flat trace.
        s = SingleLoopSolver(llm_manager=None, tool_schemas=None)  # type: ignore[arg-type]
        s.initialize("SYSTEM")
        s.inject_message("user", "U1")
        s.messages.append({"role": "assistant", "content": "A1"})
        trace = s.serialize_conversation()
        assert trace["format"] == "flat"
        path = write_conversation_json(tmp_path, trace)
        loaded = json.loads(path.read_text())
        assert loaded["format"] == "flat"
        assert loaded["messages"] == trace["messages"]

    def test_nested_roundtrip_via_hacksynth_serialize(self, tmp_path):
        # Build a nested trace by hand (HackSynthSolver covered by its
        # own tests; here we verify the persistence path is shape-faithful).
        trace = {
            "format": "nested",
            "turns": [
                {"turn": 1,
                 "agents": [{"name": "planner", "messages": [{"role": "system", "content": "S"}],
                             "response": "<command>ls</command>",
                             "usage": {"input_tokens": 5, "output_tokens": 3}},
                            {"name": "summarizer", "messages": [{"role": "system", "content": "Z"}],
                             "response": "ls returned 3 files",
                             "usage": {"input_tokens": 10, "output_tokens": 4}}],
                 "execution": {"command": "ls", "output": "a\nb\nc",
                               "summary_entry": "ls returned 3 files"}},
                {"turn": 2,
                 "agents": [{"name": "planner", "messages": [],
                             "response": "<flag>FLAG{deadbeef}</flag>",
                             "usage": {"input_tokens": 20, "output_tokens": 5}}],
                 "execution": None},
            ],
            "rolling_summary": ["ls returned 3 files"],
        }
        path = write_conversation_json(tmp_path, trace)
        loaded = json.loads(path.read_text())
        assert loaded == trace
        # Basic structural equivalence checks:
        assert len(loaded["turns"]) == 2
        assert loaded["turns"][0]["agents"][0]["name"] == "planner"
        assert loaded["turns"][0]["agents"][1]["name"] == "summarizer"
        assert loaded["turns"][1]["execution"] is None


class TestReportRendersNestedTrace:
    def _write_minimal_attempt_dir(self, tmp_path: Path, trace: dict) -> Path:
        d = tmp_path / "scan-001"
        (d / "logs").mkdir(parents=True)
        # An empty events.jsonl is enough — generate_report needs at least
        # one of (messages, events, nested-conversation) to proceed.
        (d / "logs" / "events.jsonl").write_text("")
        (d / "logs" / "solver.jsonl").write_text("")
        write_conversation_json(d, trace)
        return d

    def test_nested_report_contains_per_turn_sections(self, tmp_path):
        trace = {
            "format": "nested",
            "turns": [
                {"turn": 1,
                 "agents": [
                     {"name": "planner", "messages": [],
                      "response": "<reasoning>recon</reasoning>\n<command>id</command>",
                      "usage": {"input_tokens": 5, "output_tokens": 2}},
                     {"name": "summarizer", "messages": [],
                      "response": "id returned uid=0(root)",
                      "usage": {"input_tokens": 8, "output_tokens": 3}}],
                 "execution": {"command": "id", "output": "uid=0(root)",
                               "summary_entry": "id returned uid=0(root)"}},
            ],
            "rolling_summary": ["id returned uid=0(root)"],
        }
        scan_dir = self._write_minimal_attempt_dir(tmp_path, trace)
        report_path = generate_report(scan_dir)
        assert report_path is not None and report_path.exists()
        body = report_path.read_text()
        # Per-turn heading
        assert "### Turn 1" in body
        # Both agents rendered as collapsible details
        assert "<b>planner</b>" in body
        assert "<b>summarizer</b>" in body
        # Per-agent token usage surfaced
        assert "in: 5 / out: 2 tokens" in body
        # Execution block: command + collapsible output + summary
        assert "**Execution:**" in body
        assert "id" in body and "uid=0(root)" in body
        assert "_Summary entry:_ id returned uid=0(root)" in body
        # Final rolling memory section
        assert "Final Rolling Working Memory" in body
        assert "1. id returned uid=0(root)" in body

    def test_flat_report_unchanged(self, tmp_path):
        # Flat format takes the legacy rendering path.
        d = tmp_path / "scan-flat"
        (d / "logs").mkdir(parents=True)
        msgs = [{"role": "system", "content": "S"},
                {"role": "user", "content": "U"},
                {"role": "assistant", "content": "A"}]
        # Write solver.jsonl entries (flat path reads from here)
        (d / "logs" / "solver.jsonl").write_text(
            "\n".join(json.dumps(m) for m in msgs) + "\n"
        )
        (d / "logs" / "events.jsonl").write_text("")
        # Flat conversation.json is fine but report uses solver.jsonl for flat.
        write_conversation_json(d, msgs)
        body = generate_report(d).read_text()
        # Legacy headings appear; nested marker absent.
        assert "### System Prompt" in body
        assert "### User Message" in body
        assert "### Assistant" in body
        assert "### Turn 1" not in body
        assert "Final Rolling Working Memory" not in body

    def test_nested_only_no_solver_jsonl_still_produces_report(self, tmp_path):
        """If only conversation.json (nested) exists, that's enough to
        produce a report."""
        trace = {
            "format": "nested",
            "turns": [
                {"turn": 1,
                 "agents": [{"name": "planner", "messages": [],
                             "response": "<command>id</command>",
                             "usage": {"input_tokens": 1, "output_tokens": 1}}],
                 "execution": None}
            ],
            "rolling_summary": [],
        }
        d = tmp_path / "scan-nested-only"
        (d / "logs").mkdir(parents=True)
        # Both jsonl files empty.
        (d / "logs" / "events.jsonl").write_text("")
        (d / "logs" / "solver.jsonl").write_text("")
        write_conversation_json(d, trace)
        report = generate_report(d)
        assert report is not None
        body = report.read_text()
        assert "### Turn 1" in body
