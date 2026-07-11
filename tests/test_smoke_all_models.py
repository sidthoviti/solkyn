"""Tests for the v1 smoke validator (offline / no live LLM calls)."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.smoke_all_models import (
    _is_anthropic_model,
    _is_openrouter_model,
    _required_config_fields,
    _required_stats_fields,
    check_smoke_result,
)


def _good_stats() -> dict:
    return {
        "success": True,
        "exit_reason": "flag_found",
        "flag": "FLAG{abc}",
        "iterations": 3,
        "duration_seconds": 30.0,
        "tool_calls": 5,
        "input_tokens": 12000,
        "output_tokens": 400,
        "cache_read_input_tokens": 10000,
        "cache_creation_input_tokens": 0,
        "cost_usd": 0.045,
        "upstream_cost_usd": 0.040,
        "refusal_count": 0,
        "canary": "solkyn-canary-xyz",
        "error": None,
    }


def _good_config() -> dict:
    return {
        "challenge_id": "XBEN-058-24",
        "name": "Test",
        "level": "1",
        "tags": ["idor"],
        "target_url": "http://host.docker.internal:8000",
        "model": "gpt-5.4",
        "provider": "openai-compatible",
        "solver": "single_loop_compact",
        "mode": "whitebox",
        "max_iterations": 5,
        "expected_flag": "FLAG{abc}",
        "git_sha": "abc123",
        "kali_image_digest": "sha256:abc",
        "effective_llm_params": {"model": "gpt-5.4", "seed": 42},
    }


def _build_attempt_dir(
    tmp_path: Path,
    *,
    stats: dict | None = None,
    config: dict | None = None,
    events: list[dict] | None = None,
) -> Path:
    d = tmp_path / "20260521_120000_attempt_1"
    d.mkdir()
    if stats is not None:
        (d / "stats.json").write_text(json.dumps(stats))
    if config is not None:
        (d / "config.json").write_text(json.dumps(config))
    if events is not None:
        (d / "logs").mkdir()
        (d / "logs" / "events.jsonl").write_text(
            "\n".join(json.dumps(e) for e in events) + "\n"
        )
    return d


def test_is_openrouter_model() -> None:
    assert _is_openrouter_model("openrouter-opus47") is True
    assert _is_openrouter_model("openrouter-glm51") is True
    assert _is_openrouter_model("azure-gpt54") is False


def test_is_anthropic_model() -> None:
    assert _is_anthropic_model("openrouter-opus47", {"model": "anthropic/claude-opus-4.7"})
    assert _is_anthropic_model("openrouter-anything",
                               {"model": "anthropic/claude-sonnet"})
    assert _is_anthropic_model("openrouter-opus47", {"model": "anything"})  # by key
    assert not _is_anthropic_model("openrouter-glm51", {"model": "z-ai/glm-5.1"})


def test_required_fields_lists_nonempty() -> None:
    assert len(_required_stats_fields()) >= 10
    assert len(_required_config_fields()) >= 10


def test_no_attempt_dir_fails(tmp_path: Path) -> None:
    res = check_smoke_result("azure-gpt54", None, 0)
    assert res["passed"] is False
    names = {c["name"]: c["ok"] for c in res["checks"]}
    assert names["attempt_dir_created"] is False


def test_subprocess_failure_fails(tmp_path: Path) -> None:
    res = check_smoke_result("azure-gpt54", None, 2)
    names = {c["name"]: c["ok"] for c in res["checks"]}
    assert names["subprocess_succeeded"] is False


def test_happy_path_azure(tmp_path: Path) -> None:
    d = _build_attempt_dir(
        tmp_path,
        stats=_good_stats(),
        config=_good_config(),
        events=[{"type": "llm_call", "model": "gpt-5.4"}] * 3,
    )
    res = check_smoke_result("azure-gpt54", d, 0)
    failed = [c["name"] for c in res["checks"] if not c["ok"]]
    assert res["passed"] is True, f"Unexpected failures: {failed}"


def test_happy_path_openrouter(tmp_path: Path) -> None:
    d = _build_attempt_dir(
        tmp_path,
        stats=_good_stats(),
        config={**_good_config(), "provider": "openrouter", "model": "z-ai/glm-5.1"},
        events=[
            {"type": "llm_call", "upstream_cost_usd": 0.01},
            {"type": "llm_call", "upstream_cost_usd": 0.02},
        ],
    )
    res = check_smoke_result("openrouter-glm51", d, 0)
    failed = [c["name"] for c in res["checks"] if not c["ok"]]
    assert res["passed"] is True, f"Unexpected failures: {failed}"


def test_missing_stats_field_fails(tmp_path: Path) -> None:
    stats = _good_stats()
    del stats["refusal_count"]
    d = _build_attempt_dir(
        tmp_path, stats=stats, config=_good_config(),
        events=[{"type": "llm_call"}],
    )
    res = check_smoke_result("azure-gpt54", d, 0)
    names = {c["name"]: c["ok"] for c in res["checks"]}
    assert names["stats.refusal_count_present"] is False
    assert res["passed"] is False


def test_zero_tool_calls_fails(tmp_path: Path) -> None:
    stats = _good_stats()
    stats["tool_calls"] = 0
    d = _build_attempt_dir(
        tmp_path, stats=stats, config=_good_config(),
        events=[{"type": "llm_call"}],
    )
    res = check_smoke_result("azure-gpt54", d, 0)
    names = {c["name"]: c["ok"] for c in res["checks"]}
    assert names["tool_calls_gt_0"] is False
    assert res["passed"] is False


def test_openrouter_missing_upstream_cost_fails(tmp_path: Path) -> None:
    stats = _good_stats()
    stats["upstream_cost_usd"] = None
    d = _build_attempt_dir(
        tmp_path,
        stats=stats,
        config={**_good_config(), "provider": "openrouter", "model": "z-ai/glm-5.1"},
        events=[{"type": "llm_call"}],
    )
    res = check_smoke_result("openrouter-glm51", d, 0)
    names = {c["name"]: c["ok"] for c in res["checks"]}
    assert names["upstream_cost_captured"] is False


def test_azure_missing_upstream_cost_OK(tmp_path: Path) -> None:
    """Native Azure does NOT surface usage.cost — missing is OK."""
    stats = _good_stats()
    stats["upstream_cost_usd"] = None
    d = _build_attempt_dir(
        tmp_path, stats=stats, config=_good_config(),
        events=[{"type": "llm_call"}],
    )
    res = check_smoke_result("azure-gpt54", d, 0)
    names = {c["name"]: c["ok"] for c in res["checks"]}
    assert names["upstream_cost_captured"] is True


def test_invalid_exit_reason_fails(tmp_path: Path) -> None:
    stats = _good_stats()
    stats["exit_reason"] = "weird_new_reason"
    d = _build_attempt_dir(
        tmp_path, stats=stats, config=_good_config(),
        events=[{"type": "llm_call"}],
    )
    res = check_smoke_result("azure-gpt54", d, 0)
    names = {c["name"]: c["ok"] for c in res["checks"]}
    assert names["exit_reason_valid"] is False


def test_anthropic_cache_check_active(tmp_path: Path) -> None:
    """On a multi-iter run via Anthropic-direct, cache must be observed."""
    stats = _good_stats()
    stats["iterations"] = 3
    stats["cache_creation_input_tokens"] = 25000
    stats["cache_read_input_tokens"] = 0
    config = {
        **_good_config(),
        "model": "anthropic/claude-opus-4.7",
        "effective_llm_params": {
            "extra_body": {"provider": {"order": ["Anthropic"]}},
        },
    }
    d = _build_attempt_dir(
        tmp_path,
        stats=stats,
        config=config,
        events=[{"type": "llm_call", "upstream_cost_usd": 0.05}],
    )
    res = check_smoke_result("openrouter-opus47", d, 0)
    names = {c["name"]: c["ok"] for c in res["checks"]}
    assert names["anthropic_cache_active"] is True


def test_anthropic_cache_check_inactive(tmp_path: Path) -> None:
    """Multi-iter via Anthropic-direct with zero cache activity FAILS."""
    stats = _good_stats()
    stats["iterations"] = 3
    stats["cache_creation_input_tokens"] = 0
    stats["cache_read_input_tokens"] = 0
    config = {
        **_good_config(),
        "model": "anthropic/claude-opus-4.7",
        "effective_llm_params": {
            "extra_body": {"provider": {"order": ["Anthropic"]}},
        },
    }
    d = _build_attempt_dir(
        tmp_path,
        stats=stats,
        config=config,
        events=[{"type": "llm_call", "upstream_cost_usd": 0.05}],
    )
    res = check_smoke_result("openrouter-opus47", d, 0)
    names = {c["name"]: c["ok"] for c in res["checks"]}
    assert names["anthropic_cache_active"] is False


def test_anthropic_cache_check_skipped_single_iter(tmp_path: Path) -> None:
    """Single-iter solve via Anthropic-direct: check is skipped (PASS)."""
    stats = _good_stats()
    stats["iterations"] = 1
    stats["cache_creation_input_tokens"] = 0
    stats["cache_read_input_tokens"] = 0
    config = {
        **_good_config(),
        "model": "anthropic/claude-opus-4.7",
        "effective_llm_params": {
            "extra_body": {"provider": {"order": ["Anthropic"]}},
        },
    }
    d = _build_attempt_dir(
        tmp_path,
        stats=stats,
        config=config,
        events=[{"type": "llm_call", "upstream_cost_usd": 0.05}],
    )
    res = check_smoke_result("openrouter-opus47", d, 0)
    names = {c["name"]: c["ok"] for c in res["checks"]}
    assert names["anthropic_cache_active"] is True  # skipped == PASS


def test_anthropic_cache_check_skipped_bedrock_route(tmp_path: Path) -> None:
    """Multi-iter via Bedrock route: cache marker not honored, skip (PASS)."""
    stats = _good_stats()
    stats["iterations"] = 3
    stats["cache_creation_input_tokens"] = 0
    stats["cache_read_input_tokens"] = 0
    config = {
        **_good_config(),
        "model": "anthropic/claude-opus-4.7",
        "effective_llm_params": {
            "extra_body": {"provider": {"order": ["Amazon Bedrock"]}},
        },
    }
    d = _build_attempt_dir(
        tmp_path,
        stats=stats,
        config=config,
        events=[{"type": "llm_call", "upstream_cost_usd": 0.05}],
    )
    res = check_smoke_result("openrouter-opus47", d, 0)
    names = {c["name"]: c["ok"] for c in res["checks"]}
    assert names["anthropic_cache_active"] is True  # skipped == PASS


def test_no_llm_call_events_fails(tmp_path: Path) -> None:
    d = _build_attempt_dir(
        tmp_path,
        stats=_good_stats(),
        config=_good_config(),
        events=[{"type": "scan_start"}, {"type": "scan_end"}],
    )
    res = check_smoke_result("azure-gpt54", d, 0)
    names = {c["name"]: c["ok"] for c in res["checks"]}
    assert names["llm_call_events_present"] is False


def test_per_call_upstream_check_openrouter(tmp_path: Path) -> None:
    """OpenRouter llm_call events must have upstream_cost_usd."""
    d = _build_attempt_dir(
        tmp_path,
        stats=_good_stats(),
        config={**_good_config(), "model": "z-ai/glm-5.1"},
        events=[
            {"type": "llm_call"},  # missing upstream cost
            {"type": "llm_call"},  # missing upstream cost
        ],
    )
    res = check_smoke_result("openrouter-glm51", d, 0)
    names = {c["name"]: c["ok"] for c in res["checks"]}
    assert names["per_call_upstream_cost"] is False
