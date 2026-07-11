"""Tests for the v1 sweep runner Manifest + resume semantics."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.run_full_sweep import (
    HONEST_TERMINATIONS,
    MAX_RETRIES,
    Manifest,
    _newest_attempt_dir_for,
)


def test_empty_manifest(tmp_path: Path) -> None:
    m = Manifest(tmp_path / "manifest.jsonl")
    assert m.is_done("X", 1) is False
    assert m.error_retries_used("X", 1) == 0
    assert m.is_permanently_failed("X", 1) is False
    s = m.stats()
    assert s == {
        "completed_attempts": 0,
        "unique_challenges_touched": 0,
        "solves": 0,
        "cost_usd_so_far": 0.0,
    }


@pytest.mark.parametrize("reason", sorted(HONEST_TERMINATIONS))
def test_honest_terminations_mark_done(tmp_path: Path, reason: str) -> None:
    m = Manifest(tmp_path / "manifest.jsonl")
    m.append({
        "challenge_id": "XBEN-001-24",
        "attempt_idx": 1,
        "exit_reason": reason,
        "success": reason == "flag_found",
        "cost_usd": 0.1,
    })
    assert m.is_done("XBEN-001-24", 1) is True
    assert m.is_done("XBEN-001-24", 2) is False
    assert m.is_done("XBEN-002-24", 1) is False


def test_error_does_not_mark_done(tmp_path: Path) -> None:
    m = Manifest(tmp_path / "manifest.jsonl")
    m.append({
        "challenge_id": "XBEN-001-24",
        "attempt_idx": 1,
        "exit_reason": "error",
        "success": False,
    })
    assert m.is_done("XBEN-001-24", 1) is False
    assert m.error_retries_used("XBEN-001-24", 1) == 1


def test_error_retries_counted(tmp_path: Path) -> None:
    m = Manifest(tmp_path / "manifest.jsonl")
    for _ in range(3):
        m.append({
            "challenge_id": "XBEN-001-24",
            "attempt_idx": 1,
            "exit_reason": "error",
        })
    assert m.error_retries_used("XBEN-001-24", 1) == 3


def test_permanent_failure_marker(tmp_path: Path) -> None:
    m = Manifest(tmp_path / "manifest.jsonl")
    m.append({
        "challenge_id": "XBEN-001-24",
        "attempt_idx": 1,
        "status": "permanent_infra_failure",
        "exit_reason": "error",
    })
    assert m.is_permanently_failed("XBEN-001-24", 1) is True
    assert m.is_permanently_failed("XBEN-001-24", 2) is False
    # Permanent-failed is NOT same as honest done — runner uses both
    # checks but only "done" is the success-path branch.
    assert m.is_done("XBEN-001-24", 1) is False


def test_manifest_persists_across_instances(tmp_path: Path) -> None:
    path = tmp_path / "manifest.jsonl"
    m1 = Manifest(path)
    m1.append({
        "challenge_id": "XBEN-001-24",
        "attempt_idx": 1,
        "exit_reason": "flag_found",
        "success": True,
        "cost_usd": 0.25,
    })
    m1.append({
        "challenge_id": "XBEN-001-24",
        "attempt_idx": 2,
        "exit_reason": "max_iterations",
        "success": False,
        "cost_usd": 0.75,
    })

    # New instance reads the same file
    m2 = Manifest(path)
    assert m2.is_done("XBEN-001-24", 1) is True
    assert m2.is_done("XBEN-001-24", 2) is True
    assert m2.is_done("XBEN-001-24", 3) is False
    s = m2.stats()
    assert s["completed_attempts"] == 2
    assert s["solves"] == 1
    assert s["cost_usd_so_far"] == 1.0


def test_manifest_tolerates_corrupt_line(tmp_path: Path) -> None:
    path = tmp_path / "manifest.jsonl"
    path.write_text(
        json.dumps(
            {"challenge_id": "X", "attempt_idx": 1, "exit_reason": "flag_found"}
        )
        + "\n"
        + "{not valid json\n"
        + json.dumps(
            {"challenge_id": "Y", "attempt_idx": 1, "exit_reason": "flag_found"}
        )
        + "\n"
    )
    m = Manifest(path)
    assert m.is_done("X", 1) is True
    assert m.is_done("Y", 1) is True


def test_stats_aggregates_costs_and_solves(tmp_path: Path) -> None:
    m = Manifest(tmp_path / "manifest.jsonl")
    m.append({"challenge_id": "X", "attempt_idx": 1, "exit_reason": "flag_found",
              "success": True, "cost_usd": 0.10})
    m.append({"challenge_id": "X", "attempt_idx": 2, "exit_reason": "max_iterations",
              "success": False, "cost_usd": 0.20})
    m.append({"challenge_id": "Y", "attempt_idx": 1, "exit_reason": "flag_found",
              "success": True, "cost_usd": None})
    m.append({"challenge_id": "Y", "attempt_idx": 2, "exit_reason": "error",
              "success": False})
    s = m.stats()
    assert s["completed_attempts"] == 4
    assert s["unique_challenges_touched"] == 2
    assert s["solves"] == 2
    assert s["cost_usd_so_far"] == pytest.approx(0.30)


def test_newest_attempt_dir_picks_latest(tmp_path: Path) -> None:
    cid = "XBEN-001-24"
    challenge_dir = tmp_path / cid
    challenge_dir.mkdir()
    (challenge_dir / "20260101_000000_attempt_1").mkdir()
    (challenge_dir / "20260101_000000_attempt_1" / "stats.json").write_text("{}")
    (challenge_dir / "20260601_120000_attempt_5").mkdir()
    (challenge_dir / "20260601_120000_attempt_5" / "stats.json").write_text("{}")
    (challenge_dir / "20260301_080000_attempt_3").mkdir()
    (challenge_dir / "20260301_080000_attempt_3" / "stats.json").write_text("{}")
    newest = _newest_attempt_dir_for(cid, tmp_path)
    assert newest is not None
    assert newest.name == "20260601_120000_attempt_5"


def test_newest_attempt_dir_skips_dirs_without_stats(tmp_path: Path) -> None:
    cid = "XBEN-001-24"
    challenge_dir = tmp_path / cid
    challenge_dir.mkdir()
    (challenge_dir / "20260101_000000_attempt_1").mkdir()
    (challenge_dir / "20260101_000000_attempt_1" / "stats.json").write_text("{}")
    (challenge_dir / "20260601_120000_attempt_5").mkdir()  # no stats.json
    newest = _newest_attempt_dir_for(cid, tmp_path)
    assert newest is not None
    assert newest.name == "20260101_000000_attempt_1"


def test_newest_attempt_dir_returns_none_when_no_challenges(tmp_path: Path) -> None:
    assert _newest_attempt_dir_for("nope", tmp_path) is None


def test_max_retries_constant_matches_design() -> None:
    # Pre-registered: error tuples retried up to 2 times before
    # permanent-fail. MAX_RETRIES is the number of RETRIES after the
    # initial attempt, so 2 means 3 total attempts at most.
    assert MAX_RETRIES == 2
