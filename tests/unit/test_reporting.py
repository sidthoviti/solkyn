""" ReportGenerator: report.md, summary.md, attack_graph.md."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

from solkyn.core.reporting import (
    ReportGenerator,
    _format_transcript_for_llm,
    status_emoji,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_attempt_dir(
    tmp_path: Path,
    *,
    success: bool = True,
    canary: str = "solkyn-canary-deadbeef",
    flag: str | None = "FLAG{test}",
    cost_usd: float | None = 0.42,
) -> Path:
    """Build a fake attempt directory matching the on-disk shape produced by
    ``run_challenges.py``."""
    d = tmp_path / "attempt"
    d.mkdir()
    (d / "logs").mkdir()
    (d / "stats.json").write_text(json.dumps({
        "success": success,
        "exit_reason": "flag_found" if success else "max_iterations",
        "flag": flag,
        "iterations": 5,
        "duration_seconds": 12.3,
        "tool_calls": 7,
        "input_tokens": 1234,
        "output_tokens": 567,
        "cost_usd": cost_usd,
        "canary": canary,
    }))
    (d / "config.json").write_text(json.dumps({
        "challenge_id": "XBEN-TEST-99",
        "target_url": "http://target.example/",
        "model": "test-model",
        "mode": "whitebox",
    }))
    (d / "conversation.json").write_text(json.dumps([
        {"role": "system", "content": "you are an agent"},
        {"role": "user", "content": "attack target"},
        {"role": "assistant", "content": "running curl",
         "tool_calls": [{"name": "bash_exec", "arguments": {"command": "curl /"}}]},
        {"role": "tool", "content": "200 OK"},
        {"role": "assistant", "content": "got FLAG{test}"},
    ]))
    # Minimal solver.jsonl + events.jsonl so the existing report generator runs.
    (d / "logs" / "solver.jsonl").write_text(
        "\n".join(json.dumps(m) for m in [
            {"role": "system", "content": "you are an agent"},
            {"role": "user", "content": "attack target"},
            {"role": "assistant", "content": "running curl",
             "tool_calls": [{"name": "bash_exec", "arguments": {"command": "curl /"}}]},
            {"role": "tool", "content": "200 OK"},
        ])
    )
    (d / "logs" / "events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in [
            {"type": "scan_start", "challenge_id": "XBEN-TEST-99",
             "target_url": "http://target.example/", "model": "test-model",
             "mode": "whitebox", "tags": ["sqli"], "level": "1",
             "max_iterations": 30},
            {"type": "scan_end", "success": success, "iterations": 5,
             "flag": flag, "total_time": 12.3,
             "input_tokens": 1234, "output_tokens": 567, "tool_calls": 7},
        ])
    )
    return d


# ---------------------------------------------------------------------------
# status_emoji
# ---------------------------------------------------------------------------


class TestStatusEmoji:
    def test_success(self) -> None:
        assert status_emoji(True) == "✅"

    def test_failure_default(self) -> None:
        assert status_emoji(False) == "❌"

    def test_time_limit(self) -> None:
        assert status_emoji(False, "time_limit") == "⏱️"

    def test_cost_limit(self) -> None:
        assert status_emoji(False, "cost_limit") == "💸"

    def test_error(self) -> None:
        assert status_emoji(False, "error") == "💥"


# ---------------------------------------------------------------------------
# Transcript formatting (LLM input)
# ---------------------------------------------------------------------------


class TestTranscriptForLLM:
    def test_skips_system(self) -> None:
        out = _format_transcript_for_llm([
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "u"},
        ])
        assert "sys" not in out
        assert "u" in out

    def test_caps_total_length(self) -> None:
        msgs = [{"role": "user", "content": "x" * 10_000} for _ in range(20)]
        out = _format_transcript_for_llm(msgs, max_chars=5000)
        assert len(out) < 6000  # roughly capped


# ---------------------------------------------------------------------------
# report.md (delegates to existing generator + canary integration)
# ---------------------------------------------------------------------------


class TestReportMd:
    def test_success_status_emoji_present(self, tmp_path: Path) -> None:
        d = _make_attempt_dir(tmp_path, success=True)
        rg = ReportGenerator(d)
        path = rg.generate_report_md()
        assert path is not None and path.exists()
        body = path.read_text()
        assert "✅" in body
        assert "PASS" in body

    def test_failure_status_emoji_present(self, tmp_path: Path) -> None:
        d = _make_attempt_dir(tmp_path, success=False, flag=None)
        rg = ReportGenerator(d)
        body = rg.generate_report_md().read_text()
        assert "❌" in body
        assert "FAIL" in body

    def test_canary_appears_in_report(self, tmp_path: Path) -> None:
        d = _make_attempt_dir(tmp_path, canary="solkyn-canary-XYZ123")
        body = ReportGenerator(d).generate_report_md().read_text()
        assert "solkyn-canary-XYZ123" in body

    def test_cost_appears_in_report(self, tmp_path: Path) -> None:
        d = _make_attempt_dir(tmp_path, cost_usd=1.23)
        body = ReportGenerator(d).generate_report_md().read_text()
        assert "$1.23" in body

    def test_required_sections_present(self, tmp_path: Path) -> None:
        d = _make_attempt_dir(tmp_path)
        body = ReportGenerator(d).generate_report_md().read_text()
        assert "## Summary" in body
        assert "## Timeline" in body
        assert "## Full Conversation" in body


# ---------------------------------------------------------------------------
# summary.md (LLM)
# ---------------------------------------------------------------------------


class TestSummaryMd:
    def test_no_llm_returns_none(self, tmp_path: Path) -> None:
        d = _make_attempt_dir(tmp_path)
        assert ReportGenerator(d, llm=None).generate_summary_md() is None

    def test_writes_markdown_with_llm(self, tmp_path: Path) -> None:
        d = _make_attempt_dir(tmp_path)
        llm = MagicMock()
        llm.chat.return_value = {"content": "## Vulnerability\n\nSQLi on /login"}
        path = ReportGenerator(d, llm=llm).generate_summary_md()
        assert path is not None and path.name == "summary.md"
        body = path.read_text()
        assert "## Vulnerability" in body
        # tools must be None — no agent loop here.
        _, kwargs = llm.chat.call_args
        assert kwargs.get("tools") is None

    def test_llm_failure_returns_none(self, tmp_path: Path) -> None:
        d = _make_attempt_dir(tmp_path)
        llm = MagicMock()
        llm.chat.side_effect = RuntimeError("api down")
        assert ReportGenerator(d, llm=llm).generate_summary_md() is None
        # No file created.
        assert not (d / "summary.md").exists()

    def test_empty_llm_content_returns_none(self, tmp_path: Path) -> None:
        d = _make_attempt_dir(tmp_path)
        llm = MagicMock()
        llm.chat.return_value = {"content": ""}
        assert ReportGenerator(d, llm=llm).generate_summary_md() is None


# ---------------------------------------------------------------------------
# attack_graph.md (LLM)
# ---------------------------------------------------------------------------


class TestAttackGraphMd:
    def test_no_llm_returns_none(self, tmp_path: Path) -> None:
        d = _make_attempt_dir(tmp_path)
        assert ReportGenerator(d, llm=None).generate_attack_graph_md() is None

    def test_writes_mermaid_block(self, tmp_path: Path) -> None:
        d = _make_attempt_dir(tmp_path)
        llm = MagicMock()
        llm.chat.return_value = {"content": "```mermaid\nflowchart TD\nA-->B\n```"}
        path = ReportGenerator(d, llm=llm).generate_attack_graph_md()
        assert path is not None and path.name == "attack_graph.md"
        assert "mermaid" in path.read_text()
        assert "flowchart" in path.read_text()

    def test_llm_failure_returns_none(self, tmp_path: Path) -> None:
        d = _make_attempt_dir(tmp_path)
        llm = MagicMock()
        llm.chat.side_effect = RuntimeError("oops")
        assert ReportGenerator(d, llm=llm).generate_attack_graph_md() is None


# ---------------------------------------------------------------------------
# generate_all
# ---------------------------------------------------------------------------


class TestGenerateAll:
    def test_returns_dict_with_three_keys(self, tmp_path: Path) -> None:
        d = _make_attempt_dir(tmp_path)
        llm = MagicMock()
        llm.chat.return_value = {"content": "## Vulnerability\nSQLi"}
        out = ReportGenerator(d, llm=llm).generate_all()
        assert set(out.keys()) == {"report", "summary", "attack_graph"}
        assert out["report"] is not None
        assert out["summary"] is not None
        assert out["attack_graph"] is not None
        # All three files on disk.
        assert (d / "report.md").exists()
        assert (d / "summary.md").exists()
        assert (d / "attack_graph.md").exists()
        # LLM was called twice (summary + graph), not for report.
        assert llm.chat.call_count == 2

    def test_no_llm_only_report_md_generated(self, tmp_path: Path) -> None:
        d = _make_attempt_dir(tmp_path)
        out = ReportGenerator(d, llm=None).generate_all()
        assert out["report"] is not None
        assert out["summary"] is None
        assert out["attack_graph"] is None


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_missing_attempt_dir_returns_none(self, tmp_path: Path) -> None:
        rg = ReportGenerator(tmp_path / "doesnotexist")
        assert rg.generate_report_md() is None

    def test_no_conversation_means_no_summary(self, tmp_path: Path) -> None:
        d = tmp_path / "empty"
        d.mkdir()
        (d / "logs").mkdir()
        (d / "stats.json").write_text("{}")
        llm = MagicMock()
        llm.chat.return_value = {"content": "x"}
        assert ReportGenerator(d, llm=llm).generate_summary_md() is None
        # LLM never invoked.
        llm.chat.assert_not_called()

    def test_loads_from_solver_jsonl_when_no_conversation_json(
        self, tmp_path: Path,
    ) -> None:
        d = _make_attempt_dir(tmp_path)
        # Remove conversation.json — should fall back to logs/solver.jsonl.
        (d / "conversation.json").unlink()
        llm = MagicMock()
        llm.chat.return_value = {"content": "## Vulnerability\nFoo"}
        path = ReportGenerator(d, llm=llm).generate_summary_md()
        assert path is not None and path.exists()
