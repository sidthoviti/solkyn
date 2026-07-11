"""Per-attempt directory layout tests ( )."""

from __future__ import annotations

import json
import time
from pathlib import Path

from solkyn.agents.attempt_dir import (
    create_attempt_dir,
    next_attempt_number,
    write_config_json,
    write_conversation_json,
    write_stats_json,
)


class TestNextAttemptNumber:
    def test_empty_dir_starts_at_1(self, tmp_path: Path) -> None:
        assert next_attempt_number(tmp_path / "missing") == 1
        empty = tmp_path / "x"
        empty.mkdir()
        assert next_attempt_number(empty) == 1

    def test_skips_unrelated_subdirs(self, tmp_path: Path) -> None:
        (tmp_path / "logs").mkdir()
        (tmp_path / "20260101_000000_attempt_3").mkdir()
        (tmp_path / "garbage_attempt_99").mkdir()
        assert next_attempt_number(tmp_path) == 4

    def test_finds_highest(self, tmp_path: Path) -> None:
        for n in [1, 2, 7, 5]:
            (tmp_path / f"20260101_00000{n}_attempt_{n}").mkdir()
        assert next_attempt_number(tmp_path) == 8


class TestCreateAttemptDir:
    def test_first_run_creates_attempt_1(self, tmp_path: Path) -> None:
        d = create_attempt_dir(tmp_path, "XBEN-001-24")
        assert d.exists()
        assert d.name.endswith("_attempt_1")
        assert d.parent.name == "XBEN-001-24"

    def test_two_runs_create_two_distinct_dirs(self, tmp_path: Path) -> None:
        d1 = create_attempt_dir(tmp_path, "XBEN-001-24")
        # Sleep enough for the timestamp to change (1s resolution).
        time.sleep(1.05)
        d2 = create_attempt_dir(tmp_path, "XBEN-001-24")
        assert d1 != d2
        assert d1.name.endswith("_attempt_1")
        assert d2.name.endswith("_attempt_2")

    def test_per_challenge_isolation(self, tmp_path: Path) -> None:
        a = create_attempt_dir(tmp_path, "X-1")
        b = create_attempt_dir(tmp_path, "X-2")
        assert a.parent != b.parent
        assert a.name.endswith("_attempt_1")
        assert b.name.endswith("_attempt_1")


class TestStatsJson:
    def test_stats_round_trip(self, tmp_path: Path) -> None:
        d = create_attempt_dir(tmp_path, "X-1")
        stats = {
            "success": True,
            "exit_reason": "flag_found",
            "flag": "FLAG{abc123}",
            "iterations": 7,
            "duration_seconds": 42.5,
            "tool_calls": 12,
            "input_tokens": 1234,
            "output_tokens": 567,
            "cost_usd": 0.0123,
            "error": None,
        }
        path = write_stats_json(d, stats)
        assert path.exists()
        loaded = json.loads(path.read_text())
        assert loaded == stats

    def test_stats_schema_keys(self, tmp_path: Path) -> None:
        d = create_attempt_dir(tmp_path, "X-1")
        path = write_stats_json(d, {
            "success": False, "exit_reason": "max_iterations",
            "flag": None, "iterations": 25, "duration_seconds": 100.0,
            "tool_calls": 30, "input_tokens": 0, "output_tokens": 0,
            "cost_usd": None, "error": None,
        })
        loaded = json.loads(path.read_text())
        for key in (
            "success", "exit_reason", "flag", "iterations",
            "duration_seconds", "tool_calls", "input_tokens",
            "output_tokens", "cost_usd", "error",
        ):
            assert key in loaded


class TestConfigJson:
    def test_config_round_trip(self, tmp_path: Path) -> None:
        d = create_attempt_dir(tmp_path, "X-1")
        cfg = {
            "challenge_id": "X-1", "model": "gpt-x",
            "max_iterations": 25, "max_cost_usd": 1.0,
            "tags": ["sqli", "auth"], "expected_flag": "FLAG{ab}",
        }
        path = write_config_json(d, cfg)
        loaded = json.loads(path.read_text())
        assert loaded == cfg


class TestConversationJson:
    def test_conversation_round_trip(self, tmp_path: Path) -> None:
        d = create_attempt_dir(tmp_path, "X-1")
        msgs = [
            {"role": "system", "content": "you are a pentester"},
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": None, "tool_calls": [
                {"id": "c1", "name": "bash_exec", "arguments": {"command": "id"}},
            ]},
            {"role": "tool", "tool_call_id": "c1", "content": "uid=0"},
        ]
        path = write_conversation_json(d, msgs)
        loaded = json.loads(path.read_text())
        assert loaded["format"] == "flat"
        assert loaded["messages"] == msgs

    def test_conversation_handles_non_serializable_via_str(
        self, tmp_path: Path,
    ) -> None:
        d = create_attempt_dir(tmp_path, "X-1")
        # An object that json can't natively handle.
        class Weird:
            def __repr__(self) -> str:
                return "<weird>"

        msgs = [{"role": "system", "content": "x", "extra": Weird()}]
        path = write_conversation_json(d, msgs)
        # Should not raise; falls back to repr/str.
        loaded = json.loads(path.read_text())
        assert loaded["messages"][0]["extra"] == "<weird>"
