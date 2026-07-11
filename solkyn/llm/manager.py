"""LLM Manager — model-agnostic interface for calling LLM providers.

Supports any OpenAI-compatible API (OpenAI, LM Studio, Ollama, vLLM, Together, Groq, Azure)
via the OpenAI SDK, plus native Anthropic SDK support for Claude models.
"""

from __future__ import annotations

import logging
import random
import re
import time
from typing import Any

import anthropic
import openai

logger = logging.getLogger(__name__)

# Provider constants
PROVIDER_OPENAI = "openai"
PROVIDER_ANTHROPIC = "anthropic"

# Providers that use the OpenAI-compatible API
OPENAI_COMPATIBLE_PROVIDERS = {
    PROVIDER_OPENAI, "lm-studio", "ollama", "vllm",
    "together", "groq", "azure", "openai-compatible",
    "openrouter",
}

#  providers whose API accepts a ``seed`` kwarg. OpenAI / Azure /
# OpenRouter forward the seed to the upstream model where supported;
# Anthropic has no seed parameter; local-server backends vary.
SEED_SUPPORTING_PROVIDERS = {
    PROVIDER_OPENAI, "azure", "openai-compatible", "openrouter",
}

#  Refusal-phrase regex. Matched against assistant text content
# (case-insensitive) to track how often a model declines a pen-test
# request. The list is deliberately conservative — false positives on
# benign helpful text would make the metric worthless. Patterns tuned
# against the Anthropic / OpenAI public refusal vocabulary; kept short
# so the regex stays cheap to run on every response.
REFUSAL_PATTERNS = re.compile(
    r"(?:"
    r"i (?:can(?:'?| no)t|won'?t|am not able to|do not feel comfortable|must decline)"
    r"|against my (?:guidelines|policies)"
    r"|i cannot (?:help|assist|provide|comply)"
    r"|i'?m not (?:going to|comfortable|able to)"
    r"|i (?:will not|refuse to)"
    r")",
    re.IGNORECASE,
)

# OpenRouter defaults — applied when provider=="openrouter" and the
# corresponding fields are not explicitly set on the config.
OPENROUTER_DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"
OPENROUTER_DEFAULT_HEADERS = {
    "HTTP-Referer": "https://github.com/sidthoviti/solkyn",
    "X-Title": "Solkyn",
}

# Rate-limit (HTTP 429) handling. Azure AI Foundry deployments enforce a
# per-minute tokens-per-minute (TPM) quota; when a multi-iteration L3 run
# bursts several large calls inside one minute it trips ``RateLimitReached``
# even though no single call exceeds the budget. The window clears at the
# next minute boundary, so the correct response is to wait it out and
# continue the *same* conversation rather than fail the attempt (which
# would re-run from scratch and waste tokens). We therefore give 429s a
# dedicated, generous retry budget independent of the content-filter /
# general retry count.
#
# Note on Retry-After: Azure sends ``Retry-After: 1`` (one second) on these
# TPM 429s, which is misleading — a one-second wait never clears a
# per-minute rolling window, so honouring it literally just burns the whole
# retry budget in seconds and fails the attempt anyway (observed live). We
# therefore enforce an *escalating floor* (``_retry_after_seconds``): wait
# at least a real minute, growing toward the cap, taking the max of the
# header value and the floor.
RATE_LIMIT_MAX_RETRIES = 25
RATE_LIMIT_MIN_WAIT_SECONDS = 60.0   # floor — a per-minute window needs ~60s
RATE_LIMIT_MAX_WAIT_SECONDS = 120.0
RATE_LIMIT_DEFAULT_WAIT_SECONDS = 60.0

# Transient connection / timeout handling. A brief local network blip (DNS
# hiccup, Wi-Fi drop, TLS timeout) surfaces as ``APIConnectionError`` /
# ``APITimeoutError`` on the LLM call. Without retries this fails the whole
# attempt mid-run and wastes everything spent so far (observed live:
# "Connection error." killed an L3 attempt at iteration 3). These are
# transient and usually clear in seconds, so we retry a few times with
# short exponential backoff before giving up.
CONNECTION_MAX_RETRIES = 4
CONNECTION_BASE_WAIT_SECONDS = 2.0
CONNECTION_MAX_WAIT_SECONDS = 30.0

# Transient server-error (HTTP 5xx) handling — the Azure "Retry pattern"
# (https://learn.microsoft.com/azure/architecture/patterns/retry).
# 500/502/503/504 from Azure AI Foundry are transient faults (instance
# restart, brief overload, gateway hiccup) and should be retried with
# capped exponential backoff + jitter rather than failing the attempt.
# This is distinct from 429 (rate limit — honour Retry-After) and 4xx
# (non-transient — fail fast, do not retry). Jitter spreads retries so
# concurrent callers don't resynchronise and re-overload the service.
SERVER_ERROR_MAX_RETRIES = 5
SERVER_ERROR_BASE_WAIT_SECONDS = 2.0
SERVER_ERROR_MAX_WAIT_SECONDS = 60.0

# Anthropic prompt-caching support. Anthropic / OpenRouter→Anthropic
# only honour the cache when an explicit ``cache_control: ephemeral``
# marker is set on the system block (and optionally on the last user
# block). Without this, every iteration re-pays the full input rate
# for the (typically 25K-token) system prompt — a 5-10× cost penalty
# on multi-iteration runs. Set the marker only when the upstream is
# Anthropic; OpenAI/Azure cache automatically with no marker needed.
def _is_anthropic_upstream(provider: str, model: str, extra_body: dict | None) -> bool:
    """True iff the request will be served by an Anthropic upstream
    (native ``provider=='anthropic'`` or OpenRouter pinned to
    ``anthropic/*``). Used to decide whether to attach cache_control
    markers to the system block.
    """
    if provider == PROVIDER_ANTHROPIC:
        return True
    if provider == "openrouter" and model.startswith("anthropic/"):
        return True
    return False


class LLMManager:
    """Unified interface for calling LLM providers with tool support."""

    def __init__(self, provider: str, model: str, api_key: str | None = None, base_url: str | None = None,
                 temperature: float = 0.0, max_tokens: int = 4096,
                 extra_body: dict | None = None,
                 seed: int | None = None):
        self.provider = provider
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        #  provider-specific kwargs forwarded into
        # ``client.chat.completions.create`` via the OpenAI SDK's
        # ``extra_body`` channel. Used by OpenRouter for upstream
        # routing constraints (pin to anthropic, disallow fallbacks,
        # etc.) and could be reused for any future provider that
        # exposes vendor-specific fields outside the OpenAI schema.
        self.extra_body = extra_body
        #  deterministic-ish sampling. Forwarded into the request
        # only for providers in ``SEED_SUPPORTING_PROVIDERS``; silently
        # ignored otherwise. Note: even where supported, the OpenAI seed
        # is best-effort — same prompt + seed generally produces the same
        # response but providers do not contractually guarantee it.
        self.seed = seed
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        #  cumulative cache + upstream cost ledgers, surfaced via
        # ``get_usage()`` so the AgentResult / stats.json can report
        # cache-hit ratio and (where available) the provider-billed USD
        # ground truth alongside our locally-computed price.
        self.total_cache_read_input_tokens = 0
        self.total_cache_creation_input_tokens = 0
        self.total_upstream_cost_usd: float | None = None
        #  count of assistant responses matching the refusal
        # regex. Critical signal for the Opus probe.
        self.refusal_count = 0
        # Optional Deadline — when set, retry/backoff sleeps are excluded
        # from the deadline budget via `with deadline.pause(): time.sleep`.
        self._deadline: Any = None

        if provider in OPENAI_COMPATIBLE_PROVIDERS:
            kwargs: dict[str, Any] = {}
            if api_key:
                kwargs["api_key"] = api_key
            # OpenRouter — default base_url + attribution headers when
            # the config doesn't override them. Headers show up on the
            # OpenRouter dashboard so we can attribute spend to Solkyn
            # versus other apps using the same key.
            if provider == "openrouter":
                if not base_url:
                    base_url = OPENROUTER_DEFAULT_BASE_URL
                kwargs["default_headers"] = OPENROUTER_DEFAULT_HEADERS
            if base_url:
                kwargs["base_url"] = base_url
            if provider == "azure":
                self._client = openai.AzureOpenAI(**kwargs)
            else:
                # For providers that don't need a real key (LM Studio, Ollama)
                if not api_key and not base_url:
                    kwargs["api_key"] = api_key or "not-needed"
                elif not api_key:
                    kwargs["api_key"] = "not-needed"
                self._client = openai.OpenAI(**kwargs)
            self._provider_type = "openai"
        elif provider == PROVIDER_ANTHROPIC:
            kwargs = {}
            if api_key:
                kwargs["api_key"] = api_key
            self._client = anthropic.Anthropic(**kwargs)
            self._provider_type = "anthropic"
        else:
            supported = OPENAI_COMPATIBLE_PROVIDERS | {PROVIDER_ANTHROPIC}
            raise ValueError(
                f"Unknown provider: {provider}. "
                f"Use one of: {', '.join(sorted(supported))}"
            )

    def chat(self, messages: list[dict], tools: list[dict] | None = None, max_retries: int = 3) -> dict:
        """Send messages to the LLM, optionally with tool schemas.

        Args:
            messages: List of message dicts with 'role' and 'content' keys.
                      Roles: 'system', 'user', 'assistant', 'tool'.
            tools: Optional list of tool schemas in OpenAI function-calling format.
            max_retries: Max retries on rate limit (429) errors.

        Returns:
            Dict with:
                - 'content': str | None — text response
                - 'tool_calls': list[dict] | None — each with 'id', 'name', 'arguments' (parsed dict)
                - 'usage': dict with 'input_tokens', 'output_tokens'
        """
        # Two independent retry budgets:
        #   * ``general_retries`` — content-filter recovery, bounded by
        #     ``max_retries`` (the historical behaviour).
        #   * ``rate_limit_retries`` — HTTP 429 recovery, bounded by
        #     ``RATE_LIMIT_MAX_RETRIES``. Kept separate so a long Azure
        #     per-minute TPM window doesn't exhaust the content-filter
        #     budget and fail the call (which would waste a whole attempt).
        general_retries = 0
        rate_limit_retries = 0
        connection_retries = 0
        server_error_retries = 0
        while True:
            try:
                if self._provider_type == "openai":
                    return self._chat_openai(messages, tools)
                else:
                    return self._chat_anthropic(messages, tools)
            except openai.BadRequestError as e:
                # Azure content filter — return a safe fallback instead of crashing
                err_body = getattr(e, "body", {}) or {}
                innererr = err_body.get("innererror", {}) if isinstance(err_body, dict) else {}
                code = innererr.get("code", "") if isinstance(innererr, dict) else ""
                if "content_filter" in code or "content_filter" in str(e):
                    logger.warning(
                        "Content filter triggered (attempt %d/%d): %s",
                        general_retries + 1, max_retries, e,
                    )
                    if general_retries < max_retries:
                        general_retries += 1
                        # Strip the last user message (likely the nudge) and retry
                        if messages and messages[-1].get("role") == "user":
                            messages = messages[:-1]
                            continue
                    # Return a safe fallback so the solver loop can continue
                    return {
                        "content": "Let me try a different approach.",
                        "tool_calls": None,
                        "usage": {"input_tokens": 0, "output_tokens": 0},
                    }
                raise
            except (openai.RateLimitError, anthropic.RateLimitError) as e:
                # 429s get a dedicated retry budget (see RATE_LIMIT_* constants).
                # An Azure per-minute TPM window clears at the next minute, so we
                # honour Retry-After and wait it out rather than failing the call
                # and triggering a wasteful attempt re-run from scratch.
                if rate_limit_retries < RATE_LIMIT_MAX_RETRIES:
                    rate_limit_retries += 1
                    wait = self._retry_after_seconds(e, rate_limit_retries)
                    logger.warning(
                        "Rate limited (rl-retry %d/%d), waiting %.0fs: %s",
                        rate_limit_retries, RATE_LIMIT_MAX_RETRIES, wait, e,
                    )
                    self._sleep_excluding_deadline(wait)
                    continue
                raise
            except (
                openai.APIConnectionError,
                openai.APITimeoutError,
                anthropic.APIConnectionError,
                anthropic.APITimeoutError,
            ) as e:
                # Transient network blip — retry a few times with short
                # exponential backoff + jitter before giving up (see
                # CONNECTION_*). Has its own budget so it doesn't interact
                # with the rate-limit or content-filter paths.
                if connection_retries < CONNECTION_MAX_RETRIES:
                    connection_retries += 1
                    wait = self._backoff_with_jitter(
                        CONNECTION_BASE_WAIT_SECONDS,
                        connection_retries,
                        CONNECTION_MAX_WAIT_SECONDS,
                    )
                    logger.warning(
                        "Connection error (conn-retry %d/%d), waiting %.1fs: %s",
                        connection_retries, CONNECTION_MAX_RETRIES, wait, e,
                    )
                    self._sleep_excluding_deadline(wait)
                    continue
                raise
            except (
                openai.InternalServerError,
                anthropic.InternalServerError,
            ) as e:
                # Transient 5xx (500/502/503/504) — Azure Retry pattern:
                # capped exponential backoff with jitter. Own budget,
                # separate from 429 (rate limit) and connection faults.
                # Non-transient 4xx (400/401/403/404) are NOT caught here
                # and propagate immediately — fail fast.
                if server_error_retries < SERVER_ERROR_MAX_RETRIES:
                    server_error_retries += 1
                    wait = self._backoff_with_jitter(
                        SERVER_ERROR_BASE_WAIT_SECONDS,
                        server_error_retries,
                        SERVER_ERROR_MAX_WAIT_SECONDS,
                    )
                    logger.warning(
                        "Server error (5xx-retry %d/%d), waiting %.1fs: %s",
                        server_error_retries, SERVER_ERROR_MAX_RETRIES, wait, e,
                    )
                    self._sleep_excluding_deadline(wait)
                    continue
                raise

    def set_deadline(self, deadline: Any) -> None:
        """Attach a `solkyn.core.deadline.Deadline` so retry/backoff
        sleeps are excluded from the wall-clock budget. Pass `None` to
        clear.
        """
        self._deadline = deadline

    def _sleep_excluding_deadline(self, seconds: float) -> None:
        """Sleep, pausing the deadline (if any) so backoff doesn't
        consume the budget.
        """
        if self._deadline is None:
            time.sleep(seconds)
            return
        with self._deadline.pause():
            time.sleep(seconds)

    @staticmethod
    def _backoff_with_jitter(base: float, attempt: int, cap: float) -> float:
        """Capped exponential backoff with equal jitter (Azure Retry
        pattern). ``attempt`` is 1-based. Computes ``base * 2^(attempt-1)``
        clamped to ``cap``, then spreads the wait across ``[raw/2, raw]`` so
        concurrent callers don't resynchronise their retries and re-overload
        the service.
        """
        raw = min(cap, base * (2 ** (max(attempt, 1) - 1)))
        return raw / 2 + random.uniform(0, raw / 2)

    @staticmethod
    def _retry_after_seconds(exc: Exception, retry_count: int = 1) -> float:
        """How long to wait after a 429, as the max of the upstream
        ``Retry-After`` header and an escalating floor.

        Azure's TPM 429s carry ``Retry-After: 1`` which is far too short to
        clear a per-minute rolling window — honouring it literally just
        burns the retry budget in seconds and fails the call. So we enforce
        an escalating floor (``RATE_LIMIT_MIN_WAIT_SECONDS * retry_count``,
        clamped to ``RATE_LIMIT_MAX_WAIT_SECONDS``) and take the larger of
        that and the header value. ``retry_count`` is 1-based.
        """
        floor = min(
            RATE_LIMIT_MAX_WAIT_SECONDS,
            RATE_LIMIT_MIN_WAIT_SECONDS * max(retry_count, 1),
        )
        header_wait = 0.0
        response = getattr(exc, "response", None)
        headers = getattr(response, "headers", None)
        if headers:
            raw = headers.get("retry-after") or headers.get("Retry-After")
            if raw:
                try:
                    header_wait = float(raw)
                except (TypeError, ValueError):
                    header_wait = 0.0
        return min(max(header_wait, floor), RATE_LIMIT_MAX_WAIT_SECONDS)

    @staticmethod
    def _max_tokens_field_for_model(model: str) -> str:
        """Return ``"max_completion_tokens"`` for newer OpenAI models
        (gpt-5.x, o-series) which renamed the field, otherwise the
        original ``"max_tokens"``. Centralised so reproducibility
        logging in ``effective_params`` and the actual request use the
        exact same rule.
        """
        if any(prefix in model for prefix in ("gpt-5", "o1", "o3", "o4")):
            return "max_completion_tokens"
        return "max_tokens"

    @staticmethod
    def _inject_anthropic_cache_marker(messages: list[dict]) -> list[dict]:
        """Rewrite the first system message into the content-array form
        with a ``cache_control: ephemeral`` marker. No-op when the
        message list has no system message or when the system content
        is already an array (caller pre-formatted it). Returns a new
        list; does not mutate the caller's messages.
        """
        if not messages:
            return messages
        new = list(messages)
        for i, m in enumerate(new):
            if m.get("role") != "system":
                continue
            content = m.get("content")
            if isinstance(content, list):
                # Already block-array form — assume caller knows best.
                return new
            if not isinstance(content, str) or not content:
                return new
            new[i] = {
                "role": "system",
                "content": [
                    {
                        "type": "text",
                        "text": content,
                        "cache_control": {"type": "ephemeral"},
                    }
                ],
            }
            return new
        return new

    def _chat_openai(self, messages: list[dict], tools: list[dict] | None) -> dict:
        """Call OpenAI-compatible API."""
        # Prompt caching for OpenRouter→Anthropic: the OpenAI schema
        # accepts a content-array form on system messages that
        # OpenRouter relays to Anthropic verbatim, including the
        # ``cache_control`` marker. Rewrite the first system message
        # into that form so multi-iteration runs benefit from the same
        # 90%-off cache-read pricing the native Anthropic path enjoys.
        # Skipped (no-op) when the upstream is OpenAI/Azure/etc., where
        # caching is automatic and the marker would be ignored.
        if _is_anthropic_upstream(self.provider, self.model, self.extra_body):
            messages = self._inject_anthropic_cache_marker(messages)

        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
        }
        kwargs[self._max_tokens_field_for_model(self.model)] = self.max_tokens
        #  forward seed only for providers that accept it.
        if self.seed is not None and self.provider in SEED_SUPPORTING_PROVIDERS:
            kwargs["seed"] = self.seed
        if tools:
            kwargs["tools"] = tools
        #  vendor-specific fields (e.g. OpenRouter ``provider``
        # routing block) forwarded verbatim via the SDK's extra_body
        # passthrough.
        if self.extra_body:
            kwargs["extra_body"] = self.extra_body

        response = self._client.chat.completions.create(**kwargs)
        choice = response.choices[0]

        # Parse tool calls
        tool_calls = None
        if choice.message.tool_calls:
            tool_calls = []
            for tc in choice.message.tool_calls:
                import json
                tool_calls.append({
                    "id": tc.id,
                    "name": tc.function.name,
                    "arguments": json.loads(tc.function.arguments),
                })

        # Track usage.  also extract cached input tokens from
        # ``prompt_tokens_details.cached_tokens`` (OpenAI / Azure) so the
        # CostTracker can bill them at the discounted cache-read rate
        # instead of the full input rate. Without this, KV-cache reuse
        # across iterations (typically 70-90% of prompt) is double-counted
        # at full input price, inflating reported cost by ~5-10×.
        usage = {"input_tokens": 0, "output_tokens": 0, "cache_read_input_tokens": 0}
        if response.usage:
            usage["input_tokens"] = response.usage.prompt_tokens or 0
            usage["output_tokens"] = response.usage.completion_tokens or 0
            details = getattr(response.usage, "prompt_tokens_details", None)
            if details is not None:
                cached = getattr(details, "cached_tokens", 0) or 0
                usage["cache_read_input_tokens"] = cached
            #  OpenRouter returns the upstream-billed USD cost
            # directly on ``response.usage.cost``. Capture it as ground
            # truth alongside our tokencost-derived calculation so the
            # CostTracker can reconcile any model-pricing drift.
            upstream_cost = getattr(response.usage, "cost", None)
            if upstream_cost is not None:
                usage["upstream_cost_usd"] = float(upstream_cost)
        self._record_usage_and_refusal(usage, choice.message.content)

        return {
            "content": choice.message.content,
            "tool_calls": tool_calls,
            "usage": usage,
        }

    def _chat_anthropic(self, messages: list[dict], tools: list[dict] | None) -> dict:
        """Call Anthropic API (Claude models)."""
        # Anthropic uses a separate system parameter, not a system message
        system_text = None
        chat_messages = []
        for msg in messages:
            if msg["role"] == "system":
                system_text = msg["content"]
            elif msg["role"] == "tool":
                # Anthropic expects tool results as user messages with tool_result content blocks
                chat_messages.append({
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": msg.get("tool_call_id", ""),
                        "content": msg["content"],
                    }],
                })
            else:
                chat_messages.append({"role": msg["role"], "content": msg["content"]})

        # Convert OpenAI tool format to Anthropic format
        anthropic_tools = None
        if tools:
            anthropic_tools = []
            for tool in tools:
                func = tool["function"]
                anthropic_tools.append({
                    "name": func["name"],
                    "description": func.get("description", ""),
                    "input_schema": func.get("parameters", {"type": "object", "properties": {}}),
                })

        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": chat_messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        if system_text:
            # Prompt caching: tag the system block with the ephemeral
            # cache marker so subsequent iterations within the 5-min TTL
            # read the (typically 25K-token) playbooks/canary prefix at
            # the 10% cache-read rate instead of full input price. The
            # block-array form is the only Anthropic-native shape that
            # accepts cache_control.
            kwargs["system"] = [
                {
                    "type": "text",
                    "text": system_text,
                    "cache_control": {"type": "ephemeral"},
                }
            ]
        if anthropic_tools:
            kwargs["tools"] = anthropic_tools

        response = self._client.messages.create(**kwargs)

        # Parse response — Anthropic returns content blocks
        content_text = None
        tool_calls = None
        for block in response.content:
            if block.type == "text":
                content_text = block.text
            elif block.type == "tool_use":
                if tool_calls is None:
                    tool_calls = []
                tool_calls.append({
                    "id": block.id,
                    "name": block.name,
                    "arguments": block.input,
                })

        #  also extract cache fields so the CostTracker can bill
        # cache-read at the discounted rate. Anthropic surfaces these as
        # ``cache_read_input_tokens`` and ``cache_creation_input_tokens``
        # directly on ``response.usage``.
        usage = {
            "input_tokens": response.usage.input_tokens,
            "output_tokens": response.usage.output_tokens,
            "cache_read_input_tokens": getattr(
                response.usage, "cache_read_input_tokens", 0
            ) or 0,
            "cache_creation_input_tokens": getattr(
                response.usage, "cache_creation_input_tokens", 0
            ) or 0,
        }
        self._record_usage_and_refusal(usage, content_text)

        return {
            "content": content_text,
            "tool_calls": tool_calls,
            "usage": usage,
        }

    def _record_usage_and_refusal(self, usage: dict, assistant_text: str | None) -> None:
        """ update cumulative ledgers and refusal counter.

        Called from both ``_chat_openai`` and ``_chat_anthropic`` so the
        accounting is identical regardless of which transport handled
        the request. ``usage`` is the per-call dict already populated
        by the caller; ``assistant_text`` is the text body of the
        response (None for tool-call-only turns, in which case the
        refusal regex isn't run).
        """
        self.total_input_tokens += usage.get("input_tokens", 0) or 0
        self.total_output_tokens += usage.get("output_tokens", 0) or 0
        self.total_cache_read_input_tokens += (
            usage.get("cache_read_input_tokens", 0) or 0
        )
        self.total_cache_creation_input_tokens += (
            usage.get("cache_creation_input_tokens", 0) or 0
        )
        upstream_cost = usage.get("upstream_cost_usd")
        if upstream_cost is not None:
            # Initialise to 0.0 on first observation so the field reads
            # as "some upstream costs were captured" rather than "none
            # available" once we've seen at least one.
            if self.total_upstream_cost_usd is None:
                self.total_upstream_cost_usd = 0.0
            self.total_upstream_cost_usd += float(upstream_cost)
        if assistant_text and REFUSAL_PATTERNS.search(assistant_text):
            self.refusal_count += 1

    def get_usage(self) -> dict:
        """Return cumulative token usage and  auxiliary counters."""
        return {
            "input_tokens": self.total_input_tokens,
            "output_tokens": self.total_output_tokens,
            "cache_read_input_tokens": self.total_cache_read_input_tokens,
            "cache_creation_input_tokens": self.total_cache_creation_input_tokens,
            "upstream_cost_usd": self.total_upstream_cost_usd,
            "refusal_count": self.refusal_count,
        }

    def effective_params(self) -> dict:
        """ return the *effective* request parameter set as it
        would be sent on the next ``chat()`` call. Used by
        ``write_config_json`` so the per-attempt artefact captures
        every knob the model actually saw, including the
        max_tokens-vs-max_completion_tokens field-name swap the SDK
        does for newer OpenAI models. Reproducibility table input.
        """
        if self._provider_type == "anthropic":
            mt_field = "max_tokens"
            seed_supported = False
        else:
            mt_field = self._max_tokens_field_for_model(self.model)
            seed_supported = self.provider in SEED_SUPPORTING_PROVIDERS
        return {
            "provider": self.provider,
            "model": self.model,
            "temperature": self.temperature,
            "max_tokens_field": mt_field,
            "max_tokens_value": self.max_tokens,
            "seed": self.seed if seed_supported else None,
            "seed_supported": seed_supported,
            "extra_body": self.extra_body,
        }
