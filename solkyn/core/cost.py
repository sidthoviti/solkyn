"""CostTracker — per-model USD spend accumulator.

Holds a price table keyed by model name and accumulates USD spend from
LLM `usage` dicts. Supports the standard four-axis pricing model
(input / output / cache_read / cache_write per 1k tokens) — unset
axes default to 0.

Design choices
--------------
* **Unknown models accumulate at $0** (with a warning). We never want
  the agent to crash because we forgot to seed a price; dropped cost
  data is a known-shape gap, not a correctness bug.
* **Prices are per 1k tokens** to match every provider's published
  pricing page and avoid float precision pitfalls.
* **`record(model, usage)` is the only mutating method** — keep the
  surface narrow so the orchestrator's call site is obvious.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ModelPrice:
    """USD cost per 1,000 tokens for each token category."""

    input_per_1k: float = 0.0
    output_per_1k: float = 0.0
    cache_read_per_1k: float = 0.0
    cache_write_per_1k: float = 0.0


@dataclass
class CostTracker:
    """Accumulates USD spend across LLM calls."""

    prices: dict[str, ModelPrice] = field(default_factory=dict)
    total_usd: float = 0.0
    per_model_usd: dict[str, float] = field(default_factory=dict)
    _warned_unknown: set[str] = field(default_factory=set)

    def add_price(self, model: str, price: ModelPrice) -> None:
        self.prices[model] = price

    def record(self, model: str, usage: dict[str, int] | None) -> float:
        """Record token usage for `model`. Returns the marginal USD added.

        Recognised usage keys: `input_tokens`, `output_tokens`,
        `cache_read_input_tokens`, `cache_creation_input_tokens`.
        Missing keys default to 0.
        """
        if not usage:
            return 0.0
        price = self.prices.get(model)
        if price is None:
            if model not in self._warned_unknown:
                logger.warning(
                    "CostTracker: no price for model %r — recording $0", model,
                )
                self._warned_unknown.add(model)
            return 0.0

        input_tok = usage.get("input_tokens", 0) or 0
        output_tok = usage.get("output_tokens", 0) or 0
        cache_read_tok = usage.get("cache_read_input_tokens", 0) or 0
        cache_write_tok = usage.get("cache_creation_input_tokens", 0) or 0

        #  Both OpenAI/Azure (``prompt_tokens_details.cached_tokens``)
        # and Anthropic (``cache_read_input_tokens``) report the cached
        # portion as a SUBSET of ``input_tokens`` (not in addition to it).
        # The fresh / non-cached input is billed at the full input rate;
        # the cached input is billed at the cache-read rate. Subtract here
        # to avoid double-billing the cached tokens at the full rate.
        # ``cache_creation_input_tokens`` is Anthropic-only and is reported
        # SEPARATELY from ``input_tokens`` (it's the one-shot write cost),
        # so do NOT subtract it.
        fresh_input_tok = max(0, input_tok - cache_read_tok)

        usd = (
            fresh_input_tok * price.input_per_1k / 1000.0
            + output_tok * price.output_per_1k / 1000.0
            + cache_read_tok * price.cache_read_per_1k / 1000.0
            + cache_write_tok * price.cache_write_per_1k / 1000.0
        )
        self.total_usd += usd
        self.per_model_usd[model] = self.per_model_usd.get(model, 0.0) + usd
        return usd

    def over_budget(self, max_usd: float | None) -> bool:
        if max_usd is None:
            return False
        return self.total_usd >= max_usd


# ---------------------------------------------------------------------------
# Helpers — load price table from configs/default.yaml
# ---------------------------------------------------------------------------


def load_prices_from_config(config: dict) -> dict[str, ModelPrice]:
    """Pull model prices from a parsed default.yaml.

    Recognises an optional `pricing` block keyed by **raw model string**
    (matches `LLMManager.model`), each with the four price keys. Using
    raw model strings — not provider-config aliases — keeps the table
    aligned with what the cost tracker actually receives at record time.
    """
    pricing = (config or {}).get("pricing") or {}
    if not isinstance(pricing, dict):
        return {}

    out: dict[str, ModelPrice] = {}
    for name, p in pricing.items():
        if not isinstance(p, dict):
            continue
        out[name] = ModelPrice(
            input_per_1k=float(p.get("input_per_1k", 0.0)),
            output_per_1k=float(p.get("output_per_1k", 0.0)),
            cache_read_per_1k=float(p.get("cache_read_per_1k", 0.0)),
            cache_write_per_1k=float(p.get("cache_write_per_1k", 0.0)),
        )
    return out
