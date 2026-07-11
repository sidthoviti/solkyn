"""Offline tests for release/v1 aggregator."""

from __future__ import annotations

import json
import math
from pathlib import Path

from scripts.aggregate_results import (
    bootstrap_ci,
    compute_cost_summary,
    compute_cross_model_union,
    compute_passk_per_model,
    compute_per_level,
    compute_per_vuln_class,
    load_attempts,
    load_inventory,
    passk_unbiased,
    render_cost_summary,
    render_cross_model_union,
    render_leaderboard,
    render_passN_delta,
    render_per_level,
    render_per_vuln_class,
)

# ---- passk math --------------------------------------------------------------


def test_passk_all_success() -> None:
    assert passk_unbiased(3, 3, 1) == 1.0
    assert passk_unbiased(3, 3, 3) == 1.0


def test_passk_all_fail() -> None:
    assert passk_unbiased(3, 0, 1) == 0.0
    assert passk_unbiased(3, 0, 3) == 0.0


def test_passk_partial() -> None:
    # n=3, c=1, k=1 → 1 - C(2,1)/C(3,1) = 1 - 2/3 = 1/3
    assert math.isclose(passk_unbiased(3, 1, 1), 1 / 3)
    # n=3, c=2, k=1 → 1 - C(1,1)/C(3,1) = 1 - 1/3 = 2/3
    assert math.isclose(passk_unbiased(3, 2, 1), 2 / 3)
    # n=3, c=1, k=3 → 1 - C(2,3) = 1.0 (since n-c < k)
    assert passk_unbiased(3, 1, 3) == 1.0


def test_bootstrap_ci_constant() -> None:
    lo, hi = bootstrap_ci([0.5, 0.5, 0.5, 0.5], seed=42)
    assert math.isclose(lo, 0.5)
    assert math.isclose(hi, 0.5)


def test_bootstrap_ci_empty() -> None:
    assert bootstrap_ci([]) == (0.0, 0.0)


def test_bootstrap_ci_range() -> None:
    lo, hi = bootstrap_ci([0.0, 1.0, 0.0, 1.0, 1.0], seed=0)
    assert 0.0 <= lo <= hi <= 1.0


# ---- loading -----------------------------------------------------------------


def _make_attempt(
    root: Path, model_leg: str, cid: str, attempt: int,
    *, success: bool, cost: float = 0.01, upstream: float | None = None,
) -> None:
    d = root / model_leg / cid / f"20260101_000000_attempt_{attempt}"
    d.mkdir(parents=True)
    (d / "stats.json").write_text(json.dumps({
        "success": success,
        "exit_reason": "flag_found" if success else "max_iterations",
        "iterations": 10,
        "duration_seconds": 30.0,
        "tool_calls": 5,
        "input_tokens": 1000,
        "output_tokens": 200,
        "cache_read_input_tokens": 0,
        "cache_creation_input_tokens": 0,
        "cost_usd": cost,
        "upstream_cost_usd": upstream,
        "refusal_count": 0,
        "error": None,
    }))


def test_load_attempts_basic(tmp_path: Path) -> None:
    _make_attempt(tmp_path, "azure-gpt54-whitebox", "XBEN-001-24", 1, success=True)
    _make_attempt(tmp_path, "azure-gpt54-whitebox", "XBEN-001-24", 2, success=False)
    _make_attempt(tmp_path, "openrouter-opus47-whitebox", "XBEN-001-24", 1,
                  success=True, upstream=0.02)
    rows = load_attempts(tmp_path)
    assert len(rows) == 3
    assert {r["model"] for r in rows} == {"azure-gpt54", "openrouter-opus47"}
    assert all(r["leg"] == "whitebox" for r in rows)


def test_load_attempts_missing_root(tmp_path: Path) -> None:
    rows = load_attempts(tmp_path / "nope")
    assert rows == []


def test_load_attempts_skips_bad_json(tmp_path: Path) -> None:
    d = tmp_path / "azure-gpt54-whitebox" / "XBEN-001-24" / "attempt_1"
    d.mkdir(parents=True)
    (d / "stats.json").write_text("not json {")
    rows = load_attempts(tmp_path)
    assert rows == []


def test_load_inventory_missing(tmp_path: Path) -> None:
    inv = load_inventory(tmp_path / "missing.json")
    assert inv == {}


# ---- aggregation -------------------------------------------------------------


def _attempt_row(model: str, cid: str, success: bool,
                 leg: str = "whitebox", **kw) -> dict:
    return {
        "model": model, "leg": leg, "challenge_id": cid,
        "attempt": 1, "attempt_dir": "/tmp/x",
        "success": success, "exit_reason": "flag_found" if success else "max_iterations",
        "iterations": 10, "duration_seconds": 30.0,
        "tool_calls": 5, "input_tokens": 1000, "output_tokens": 200,
        "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0,
        "cost_usd": kw.get("cost", 0.01),
        "upstream_cost_usd": kw.get("upstream"),
        "refusal_count": 0, "error": None,
    }


def test_compute_passk_per_model() -> None:
    rows = [
        # azure: XBEN-001 succeeds 3/3
        _attempt_row("azure", "XBEN-001-24", True),
        _attempt_row("azure", "XBEN-001-24", True),
        _attempt_row("azure", "XBEN-001-24", True),
        # azure: XBEN-002 fails 0/3
        _attempt_row("azure", "XBEN-002-24", False),
        _attempt_row("azure", "XBEN-002-24", False),
        _attempt_row("azure", "XBEN-002-24", False),
    ]
    passk = compute_passk_per_model(rows)
    info = passk[("azure", "whitebox")]
    # pass@1 = mean of [1.0, 0.0] = 0.5
    assert math.isclose(info["passk"]["pass@1"]["mean"], 0.5)
    # pass@3 = mean of [1.0, 0.0] = 0.5
    assert math.isclose(info["passk"]["pass@3"]["mean"], 0.5)


def test_compute_per_level() -> None:
    rows = [_attempt_row("m", "XBEN-001-24", True)]
    inv = {"XBEN-001-24": {"level": "1", "tags": ["idor"]}}
    out = compute_per_level(rows, inv)
    assert "1" in out[("m", "whitebox")]


def test_compute_per_vuln_class() -> None:
    rows = [_attempt_row("m", "XBEN-001-24", True)]
    inv = {"XBEN-001-24": {"level": "1", "tags": ["sqli"]}}
    out = compute_per_vuln_class(rows, inv)
    assert "sqli" in out[("m", "whitebox")]


def test_compute_cross_model_union() -> None:
    rows = [
        _attempt_row("m1", "XBEN-001-24", True),
        _attempt_row("m2", "XBEN-001-24", False),
        _attempt_row("m1", "XBEN-002-24", False),
        _attempt_row("m2", "XBEN-002-24", True),
        _attempt_row("m1", "XBEN-003-24", False),
        _attempt_row("m2", "XBEN-003-24", False),
    ]
    out = compute_cross_model_union(rows)
    assert out["total_challenges"] == 3
    assert out["union_solved"] == 2
    assert set(out["per_model_solo_solves"]["m1"]) == {"XBEN-001-24"}
    assert set(out["per_model_solo_solves"]["m2"]) == {"XBEN-002-24"}


def test_compute_cross_model_union_blackbox_filtered() -> None:
    rows = [
        _attempt_row("m1", "XBEN-001-24", True, leg="blackbox"),
        _attempt_row("m2", "XBEN-001-24", True, leg="whitebox"),
    ]
    out = compute_cross_model_union(rows)
    # blackbox is filtered out → only m2/wb seen
    assert out["total_challenges"] == 1
    assert out["per_model_solo_solves"]["m2"] == ["XBEN-001-24"]
    assert "m1" not in out["per_model_solo_solves"]


def test_compute_cost_summary() -> None:
    rows = [
        _attempt_row("m1", "X", True, cost=0.05, upstream=0.04),
        _attempt_row("m1", "Y", False, cost=0.03, upstream=None),
        _attempt_row("m2", "X", True, cost=0.10, upstream=0.09),
    ]
    out = compute_cost_summary(rows)
    assert math.isclose(out["m1-whitebox"]["cost_usd_local"], 0.08)
    assert math.isclose(out["m1-whitebox"]["upstream_cost_usd"], 0.04)
    assert out["m1-whitebox"]["upstream_attempts"] == 1
    assert out["m1-whitebox"]["n_attempts"] == 2


# ---- rendering ---------------------------------------------------------------


def test_render_leaderboard() -> None:
    passk = {
        ("m1", "whitebox"): {
            "per_challenge": {},
            "passk": {
                "pass@1": {"mean": 0.5, "ci_low": 0.4, "ci_high": 0.6, "n_challenges": 10},
                "pass@3": {"mean": 0.7, "ci_low": 0.6, "ci_high": 0.8, "n_challenges": 10},
            },
        },
    }
    out = render_leaderboard(passk)
    assert "m1" in out
    assert "50.0%" in out
    assert "70.0%" in out


def test_render_per_level_smoke() -> None:
    pl = {
        ("m1", "whitebox"): {
            "1": {"pass@1": {"mean": 1.0, "n": 5}, "pass@3": {"mean": 1.0, "n": 5}},
            "3": {"pass@1": {"mean": 0.2, "n": 3}, "pass@3": {"mean": 0.5, "n": 3}},
        },
    }
    out = render_per_level(pl)
    assert "L1" in out and "L3" in out


def test_render_per_vuln_class_smoke() -> None:
    pv = {("m1", "whitebox"): {
        "sqli": {"pass@1": {"mean": 0.8, "n": 5}, "pass@3": {"mean": 0.9, "n": 5}}
    }}
    out = render_per_vuln_class(pv)
    assert "sqli" in out


def test_render_cross_model_union_smoke() -> None:
    union = {
        "total_challenges": 100,
        "union_solved": 95,
        "union_solved_ids": [],
        "per_model_solo_solves": {"m1": ["XBEN-001-24"], "m2": []},
        "per_challenge_solvers": {},
    }
    out = render_cross_model_union(union)
    assert "95" in out and "m1" in out


def test_render_passN_delta_smoke() -> None:
    passk = {
        ("m1", "whitebox"): {
            "per_challenge": {},
            "passk": {
                "pass@1": {"mean": 0.5},
                "pass@3": {"mean": 0.7},
            },
        },
    }
    out = render_passN_delta(passk)
    assert "m1" in out and "+20.0%" in out


def test_render_cost_summary_smoke() -> None:
    cost = {"m1-whitebox": {
        "n_attempts": 10, "cost_usd_local": 1.23,
        "upstream_cost_usd": 1.20, "upstream_attempts": 10,
    }}
    out = render_cost_summary(cost)
    assert "$1.23" in out and "$1.20" in out


# ---- end-to-end --------------------------------------------------------------


def test_end_to_end(tmp_path: Path) -> None:
    """Build a tiny sweep tree, run all steps, verify outputs."""
    _make_attempt(tmp_path, "azure-gpt54-whitebox", "XBEN-001-24", 1,
                  success=True, cost=0.05)
    _make_attempt(tmp_path, "azure-gpt54-whitebox", "XBEN-001-24", 2,
                  success=True, cost=0.05)
    _make_attempt(tmp_path, "openrouter-opus47-whitebox", "XBEN-001-24", 1,
                  success=False, cost=0.10, upstream=0.09)

    rows = load_attempts(tmp_path)
    assert len(rows) == 3

    passk = compute_passk_per_model(rows)
    assert ("azure-gpt54", "whitebox") in passk

    union = compute_cross_model_union(rows)
    assert union["union_solved"] == 1
