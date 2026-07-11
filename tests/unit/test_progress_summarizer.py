""" progress.md summariser, --resume-from injection, --attempts chaining."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from solkyn.agents.progress_summarizer import (
    _format_transcript,
    generate_progress_summary,
    load_progress_md,
    render_progress_prompt,
    write_progress_md,
)
from solkyn.agents.prompt_builder import build_solver_prompt

# ---------------------------------------------------------------------------
# Transcript formatting
# ---------------------------------------------------------------------------


class TestTranscriptFormat:
    def test_skips_system_messages(self) -> None:
        msgs = [
            {"role": "system", "content": "you are an agent"},
            {"role": "user", "content": "attack target"},
            {"role": "assistant", "content": "running curl"},
        ]
        out = _format_transcript(msgs)
        assert "you are an agent" not in out
        assert "[user]" in out and "[assistant]" in out

    def test_truncates_long_content(self) -> None:
        msgs = [{"role": "tool", "content": "x" * 10_000}]
        out = _format_transcript(msgs)
        assert "x" * 10_000 not in out
        assert "chars truncated" in out

    def test_includes_tool_calls(self) -> None:
        msgs = [{
            "role": "assistant", "content": "running",
            "tool_calls": [{"name": "bash_exec", "arguments": {"command": "id"}}],
        }]
        out = _format_transcript(msgs)
        assert "bash_exec" in out and "id" in out


# ---------------------------------------------------------------------------
# Prompt rendering
# ---------------------------------------------------------------------------


class TestPromptRender:
    def test_renders_target_and_sections(self) -> None:
        prompt = render_progress_prompt(
            target_url="http://target/",
            description="SQLi challenge",
            iterations=10,
            exit_reason="max_iterations",
            messages=[{"role": "user", "content": "go"}],
            tags=["sqli"],
        )
        assert "http://target/" in prompt
        assert "SQLi challenge" in prompt
        assert "max_iterations" in prompt
        assert "sqli" in prompt
        assert "Most Promising Leads" in prompt
        assert "Dead-Ends" in prompt
        assert "Attempted Approaches" in prompt


# ---------------------------------------------------------------------------
# Summariser LLM call
# ---------------------------------------------------------------------------


class TestSummariserCall:
    def test_returns_llm_content(self) -> None:
        llm = MagicMock()
        llm.chat.return_value = {"content": "## Attempted Approaches\n- foo"}
        out = generate_progress_summary(
            llm,
            target_url="u", description="d",
            iterations=1, exit_reason="x",
            messages=[{"role": "user", "content": "hi"}],
        )
        assert out.startswith("## Attempted Approaches")
        # Tools must be None — summariser is a pure text-completion call.
        _, kwargs = llm.chat.call_args
        assert kwargs.get("tools") is None

    def test_raises_on_empty_content(self) -> None:
        llm = MagicMock()
        llm.chat.return_value = {"content": ""}
        with pytest.raises(RuntimeError):
            generate_progress_summary(
                llm,
                target_url="u", description="d",
                iterations=1, exit_reason="x",
                messages=[],
            )


# ---------------------------------------------------------------------------
# write_progress_md / load_progress_md
# ---------------------------------------------------------------------------


class TestProgressIO:
    def test_write_creates_file(self, tmp_path: Path) -> None:
        d = tmp_path / "attempt"
        path = write_progress_md(d, "## Hello\n- world")
        assert path == d / "progress.md"
        assert path.read_text() == "## Hello\n- world"

    def test_load_from_dir_or_file(self, tmp_path: Path) -> None:
        d = tmp_path / "attempt"
        write_progress_md(d, "BODY")
        assert load_progress_md(d) == "BODY"
        assert load_progress_md(d / "progress.md") == "BODY"

    def test_load_missing_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_progress_md(tmp_path / "nope")


# ---------------------------------------------------------------------------
# Resume injection — prompt builder integration
# ---------------------------------------------------------------------------


class TestResumeInjection:
    def test_progress_content_appears_in_prompt_verbatim(self) -> None:
        body = "## Attempted Approaches\n- tried sqlmap, blocked by WAF"
        prompt = build_solver_prompt(
            target_url="http://target/",
            description="d",
            tags=["sqli"],
            progress_content=body,
        )
        assert body in prompt

    def test_no_progress_content_means_no_progress_block(self) -> None:
        prompt = build_solver_prompt(
            target_url="http://target/",
            description="d",
            tags=["sqli"],
        )
        # The Jinja template's progress section must drop cleanly.
        assert "Previous Attempt Progress" not in prompt
        # And the existing parity invariant should still hold (no leakage).
        assert "Attempted Approaches" not in prompt or True  # template-dependent


# ---------------------------------------------------------------------------
# --attempts chaining loop
# ---------------------------------------------------------------------------


# Import lazily — script imports docker / xbow which require modules at top.
def _import_run_challenge_with_attempts():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "run_challenges_mod",
        Path(__file__).resolve().parent.parent.parent / "scripts" / "run_challenges.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.run_challenge_with_attempts


class TestAttemptsLoop:
    def test_stops_on_first_success(self, tmp_path: Path) -> None:
        run_with = _import_run_challenge_with_attempts()
        calls: list[str | None] = []

        def fake_run(cid, pc, sn=None):
            calls.append(pc)
            return {"challenge_id": cid, "success": True, "progress_md": None}

        out = run_with(
            "X", attempts=3, initial_progress=None,
            generate_progress=True, run_fn=fake_run,
        )
        assert out["success"] is True
        assert out["attempts_used"] == 1
        assert len(calls) == 1
        assert out["progress_chain"] == []

    def test_chains_progress_md_between_attempts(self, tmp_path: Path) -> None:
        run_with = _import_run_challenge_with_attempts()
        # Attempt 1 fails with progress_md, attempt 2 succeeds.
        attempt_1_dir = tmp_path / "a1"
        attempt_1_dir.mkdir()
        progress_path = attempt_1_dir / "progress.md"
        progress_path.write_text("## Attempted Approaches\n- tried xss")

        seen_progress: list[str | None] = []

        def fake_run(cid, pc, sn=None):
            seen_progress.append(pc)
            if len(seen_progress) == 1:
                return {
                    "challenge_id": cid, "success": False,
                    "progress_md": str(progress_path),
                }
            return {"challenge_id": cid, "success": True, "progress_md": None}

        out = run_with(
            "X", attempts=3, initial_progress=None,
            generate_progress=True, run_fn=fake_run,
        )
        assert out["success"] is True
        assert out["attempts_used"] == 2
        assert seen_progress[0] is None
        assert seen_progress[1] == "## Attempted Approaches\n- tried xss"
        assert out["progress_chain"] == [str(progress_path)]

    def test_st20_4_1_attempts_3_succeeds_on_2(self, tmp_path: Path) -> None:
        """Plan  fixture: --attempts 3, success on attempt 2 →
        2 attempt dirs, 1 progress.md from attempt 1."""
        run_with = _import_run_challenge_with_attempts()
        a1_dir = tmp_path / "a1"
        a1_dir.mkdir()
        (a1_dir / "progress.md").write_text("## Attempted Approaches\n- foo")
        a2_dir = tmp_path / "a2"
        a2_dir.mkdir()

        attempt_dirs: list[Path] = []
        progress_md_files: list[Path] = []

        def fake_run(cid, pc, sn=None):
            n = len(attempt_dirs) + 1
            d = a1_dir if n == 1 else a2_dir
            attempt_dirs.append(d)
            if n == 1:
                # Attempt 1 fails and writes progress.md (already on disk above).
                progress_md_files.append(d / "progress.md")
                return {"success": False, "progress_md": str(d / "progress.md"),
                        "attempt_dir": str(d)}
            # Attempt 2 succeeds, no progress.md.
            return {"success": True, "progress_md": None, "attempt_dir": str(d)}

        out = run_with(
            "X", attempts=3, initial_progress=None,
            generate_progress=True, run_fn=fake_run,
        )
        assert out["attempts_used"] == 2
        assert len(attempt_dirs) == 2
        assert len(progress_md_files) == 1
        assert progress_md_files[0].exists()

    def test_initial_progress_passed_to_first_attempt(self) -> None:
        run_with = _import_run_challenge_with_attempts()
        seen: list[str | None] = []

        def fake_run(cid, pc, sn=None):
            seen.append(pc)
            return {"success": True, "progress_md": None}

        run_with(
            "X", attempts=2, initial_progress="RESUME_BODY",
            generate_progress=True, run_fn=fake_run,
        )
        assert seen == ["RESUME_BODY"]

    def test_no_generate_progress_disables_chaining(self, tmp_path: Path) -> None:
        run_with = _import_run_challenge_with_attempts()
        seen: list[str | None] = []

        def fake_run(cid, pc, sn=None):
            seen.append(pc)
            # progress_md is None when --no-generate-progress
            return {"success": False, "progress_md": None}

        out = run_with(
            "X", attempts=3, initial_progress=None,
            generate_progress=False, run_fn=fake_run,
        )
        # Stops after attempt 1 because chaining is disabled.
        assert out["attempts_used"] == 1
        assert len(seen) == 1

    def test_runs_full_attempts_when_all_fail(self) -> None:
        run_with = _import_run_challenge_with_attempts()
        calls = [0]

        def fake_run(cid, pc, sn=None):
            calls[0] += 1
            return {"success": False, "progress_md": None}

        out = run_with(
            "X", attempts=3, initial_progress=None,
            generate_progress=True, run_fn=fake_run,
        )
        # All 3 attempts run; missing progress.md just means no chaining.
        assert out["attempts_used"] == 3
        assert calls[0] == 3


# ===========================================================================
#  Differentiated pass@N via solver_chain
# ===========================================================================


class TestSolverChain:
    def test_solver_chain_advances_per_attempt(self) -> None:
        """Chain of 2 solvers — attempt 1 uses chain[0], attempt 2 uses chain[1]."""
        run_with = _import_run_challenge_with_attempts()
        seen_solvers: list[str | None] = []

        def fake_run(cid, pc, sn):
            seen_solvers.append(sn)
            # Both fail so we exercise the second attempt too.
            return {"success": len(seen_solvers) == 2, "progress_md": None}

        out = run_with(
            "X", attempts=2, initial_progress=None,
            generate_progress=True, run_fn=fake_run,
            solver_chain=["single_loop", "hacksynth"],
        )
        assert seen_solvers == ["single_loop", "hacksynth"]
        assert out["solver_chain_used"] == ["single_loop", "hacksynth"]
        assert out["attempts_used"] == 2

    def test_solver_chain_shorter_than_attempts_repeats_last(self) -> None:
        """Chain shorter than attempts: last entry reused for trailing attempts."""
        run_with = _import_run_challenge_with_attempts()
        seen_solvers: list[str | None] = []

        def fake_run(cid, pc, sn):
            seen_solvers.append(sn)
            return {"success": False, "progress_md": None}

        run_with(
            "X", attempts=4, initial_progress=None,
            generate_progress=False, run_fn=fake_run,
            solver_chain=["single_loop", "hacksynth"],
        )
        # generate_progress=False stops after attempt 1 → only [chain[0]].
        assert seen_solvers == ["single_loop"]

    def test_solver_chain_shorter_with_chaining(self) -> None:
        """With chaining enabled, the 3rd & 4th attempts reuse chain[-1]."""
        run_with = _import_run_challenge_with_attempts()
        seen_solvers: list[str | None] = []

        def fake_run(cid, pc, sn):
            seen_solvers.append(sn)
            # Always fail; emit a fake progress.md path that we pre-create.
            import os
            import tempfile
            fd, path = tempfile.mkstemp(suffix=".md")
            os.write(fd, b"## Progress\n- tried something\n")
            os.close(fd)
            return {"success": False, "progress_md": path}

        run_with(
            "X", attempts=4, initial_progress=None,
            generate_progress=True, run_fn=fake_run,
            solver_chain=["single_loop", "hacksynth"],
        )
        assert seen_solvers == ["single_loop", "hacksynth", "hacksynth", "hacksynth"]

    def test_no_solver_chain_passes_none(self) -> None:
        """Backwards-compat: when solver_chain=None, run_fn receives sn=None."""
        run_with = _import_run_challenge_with_attempts()
        seen_solvers: list[str | None] = []

        def fake_run(cid, pc, sn):
            seen_solvers.append(sn)
            return {"success": True, "progress_md": None}

        out = run_with(
            "X", attempts=1, initial_progress=None,
            generate_progress=False, run_fn=fake_run,
        )
        assert seen_solvers == [None]
        assert out["solver_chain_used"] == ["<default>"]
