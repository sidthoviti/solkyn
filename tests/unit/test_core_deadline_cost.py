"""Deadline + CostTracker tests ( ) — pause-aware time
budget and per-model USD spend accumulator.
"""

from __future__ import annotations

import time

import pytest

from solkyn.core.cost import CostTracker, ModelPrice, load_prices_from_config
from solkyn.core.deadline import Deadline

# ---------------------------------------------------------------------------
# Deadline
# ---------------------------------------------------------------------------


class TestDeadline:
    def test_unbounded_never_expires(self) -> None:
        d = Deadline(max_seconds=None)
        assert d.expired is False
        assert d.remaining is None

    def test_expires_after_max(self) -> None:
        d = Deadline(max_seconds=0.05)
        time.sleep(0.07)
        assert d.expired is True
        assert d.remaining == 0.0

    def test_remaining_decreases(self) -> None:
        d = Deadline(max_seconds=1.0)
        r0 = d.remaining
        assert r0 is not None
        time.sleep(0.05)
        r1 = d.remaining
        assert r1 is not None
        assert r1 < r0

    def test_pause_excludes_time_from_budget(self) -> None:
        d = Deadline(max_seconds=0.10)
        time.sleep(0.04)
        with d.pause():
            time.sleep(0.10)  # would expire if counted
        # After pause: still ~0.04 elapsed, ~0.06 remaining.
        assert d.expired is False
        assert d.remaining is not None and d.remaining > 0.04

    def test_pause_not_reentrant(self) -> None:
        d = Deadline(max_seconds=1.0)
        with d.pause():
            with pytest.raises(RuntimeError):
                with d.pause():
                    pass

    def test_elapsed_during_pause_is_frozen(self) -> None:
        d = Deadline(max_seconds=10.0)
        time.sleep(0.02)
        with d.pause():
            e1 = d.elapsed
            time.sleep(0.05)
            e2 = d.elapsed
        # Elapsed should not grow during pause.
        assert abs(e2 - e1) < 0.01


# ---------------------------------------------------------------------------
# CostTracker
# ---------------------------------------------------------------------------


class TestCostTracker:
    def test_empty_starts_at_zero(self) -> None:
        ct = CostTracker()
        assert ct.total_usd == 0.0
        assert ct.over_budget(None) is False
        assert ct.over_budget(1.0) is False

    def test_record_known_model(self) -> None:
        ct = CostTracker(prices={
            "gpt-x": ModelPrice(input_per_1k=0.001, output_per_1k=0.002),
        })
        added = ct.record("gpt-x", {"input_tokens": 1000, "output_tokens": 500})
        assert added == pytest.approx(0.002)  # 1*0.001 + 0.5*0.002
        assert ct.total_usd == pytest.approx(0.002)
        assert ct.per_model_usd["gpt-x"] == pytest.approx(0.002)

    def test_record_accumulates_across_calls(self) -> None:
        ct = CostTracker(prices={"m": ModelPrice(input_per_1k=0.01)})
        ct.record("m", {"input_tokens": 1000})
        ct.record("m", {"input_tokens": 500})
        assert ct.total_usd == pytest.approx(0.015)

    def test_unknown_model_warns_once_and_charges_zero(self) -> None:
        ct = CostTracker()
        ct.record("ghost", {"input_tokens": 1000})
        ct.record("ghost", {"input_tokens": 1000})
        assert ct.total_usd == 0.0
        assert "ghost" in ct._warned_unknown

    def test_over_budget_threshold(self) -> None:
        ct = CostTracker(prices={"m": ModelPrice(input_per_1k=1.0)})
        ct.record("m", {"input_tokens": 50})  # $0.05
        assert ct.over_budget(1.0) is False
        assert ct.over_budget(0.05) is True
        assert ct.over_budget(0.04) is True

    def test_cache_tokens_costed(self) -> None:
        # ``cache_read_input_tokens`` is a SUBSET of ``input_tokens``
        # (both providers report it that way), so the fresh-input portion is
        # ``input_tokens - cache_read_input_tokens``. ``cache_creation_input_tokens``
        # is reported separately by Anthropic and is NOT subtracted.
        ct = CostTracker(prices={"m": ModelPrice(
            input_per_1k=0.01, output_per_1k=0.02,
            cache_read_per_1k=0.001, cache_write_per_1k=0.05,
        )})
        ct.record("m", {
            "input_tokens": 1000,
            "output_tokens": 1000,
            "cache_read_input_tokens": 1000,
            "cache_creation_input_tokens": 1000,
        })
        # fresh_input = 1000 - 1000 = 0
        # cost = 0 * 0.01 + 1000 * 0.02 + 1000 * 0.001 + 1000 * 0.05 = 0.071
        assert ct.total_usd == pytest.approx(0.071)

    def test_cache_read_subtracted_from_billable_input(self) -> None:
        """explicit demonstration of the over-billing fix.

        Before : 100k input @ $5/M (with 80k cached) was billed as
        100k * $5/M = $0.50 — the cached 80k were double-counted.
        After : fresh = 20k * $5/M = $0.10, cached = 80k * $0.50/M = $0.04,
        total = $0.14 — a 3.6× reduction matching real Azure billing.
        """
        # $5/M input = $0.005/k; $0.50/M cache_read = $0.0005/k
        ct = CostTracker(prices={"gpt5": ModelPrice(
            input_per_1k=0.005, output_per_1k=0.015, cache_read_per_1k=0.0005,
        )})
        ct.record("gpt5", {
            "input_tokens": 100_000,
            "output_tokens": 0,
            "cache_read_input_tokens": 80_000,
        })
        # fresh_input = 100_000 - 80_000 = 20_000
        # cost = 20_000 * 0.005 / 1000 + 80_000 * 0.0005 / 1000 = 0.10 + 0.04 = 0.14
        assert ct.total_usd == pytest.approx(0.14)

    def test_cache_read_clamped_when_exceeds_input(self) -> None:
        """Defensive: if a buggy provider reports cache_read > input_tokens
        (shouldn't happen, but the API surface allows it), fresh_input
        clamps to 0 instead of going negative and producing a rebate."""
        ct = CostTracker(prices={"m": ModelPrice(
            input_per_1k=1.0, cache_read_per_1k=0.1,
        )})
        ct.record("m", {
            "input_tokens": 100,
            "cache_read_input_tokens": 200,  # > input_tokens
        })
        # fresh_input clamped to 0; cost = 0 + 200 * 0.1 / 1000 = 0.02
        assert ct.total_usd == pytest.approx(0.02)

    def test_empty_usage_records_zero(self) -> None:
        ct = CostTracker(prices={"m": ModelPrice(input_per_1k=1.0)})
        assert ct.record("m", None) == 0.0
        assert ct.record("m", {}) == 0.0
        assert ct.total_usd == 0.0

    def test_load_prices_from_config(self) -> None:
        cfg = {"pricing": {
            "azure-gpt54": {"input_per_1k": 0.005, "output_per_1k": 0.015},
            "claude-sonnet": {
                "input_per_1k": 0.003, "output_per_1k": 0.015,
                "cache_read_per_1k": 0.0003, "cache_write_per_1k": 0.00375,
            },
        }}
        prices = load_prices_from_config(cfg)
        assert prices["azure-gpt54"].input_per_1k == 0.005
        assert prices["azure-gpt54"].output_per_1k == 0.015
        assert prices["claude-sonnet"].cache_read_per_1k == 0.0003

    def test_load_prices_handles_missing_section(self) -> None:
        assert load_prices_from_config({}) == {}
        assert load_prices_from_config({"pricing": None}) == {}
        assert load_prices_from_config(None) == {}  # type: ignore[arg-type]
