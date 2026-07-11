"""Structured event logging — BoxPwnr-style traces for analysis and debugging.

Events are logged to a JSONL file with timestamps, types, and structured data.
This enables post-run analysis, comparison across models, and debugging.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class EventLogger:
    """Log structured events to a JSONL file for post-run analysis."""

    def __init__(self, scan_dir: str | None = None) -> None:
        self._events: list[dict] = []
        self._log_path: Path | None = None
        self._start_time = time.time()

        if scan_dir:
            log_dir = Path(scan_dir) / "logs"
            log_dir.mkdir(parents=True, exist_ok=True)
            self._log_path = log_dir / "events.jsonl"

    def _emit(self, event_type: str, data: dict[str, Any]) -> None:
        """Emit a structured event."""
        event = {
            "timestamp": time.time(),
            "elapsed": round(time.time() - self._start_time, 2),
            "type": event_type,
            **data,
        }
        self._events.append(event)

        if self._log_path:
            with open(self._log_path, "a") as f:
                f.write(json.dumps(event, default=str) + "\n")

    def scan_start(
        self,
        challenge_id: str,
        target_url: str,
        description: str,
        tags: list[str],
        level: str,
        model: str,
        max_iterations: int,
        mode: str = "whitebox",
    ) -> None:
        self._start_time = time.time()
        self._emit("scan_start", {
            "challenge_id": challenge_id,
            "target_url": target_url,
            "description": description,
            "tags": tags,
            "level": level,
            "model": model,
            "max_iterations": max_iterations,
            "mode": mode,
        })

    def iteration_start(self, iteration: int, max_iterations: int) -> None:
        self._emit("iteration_start", {
            "iteration": iteration,
            "max_iterations": max_iterations,
        })

    def llm_call(
        self,
        iteration: int,
        input_tokens: int,
        output_tokens: int,
        duration: float,
        has_tool_calls: bool,
        reasoning: str | None = None,
        upstream_cost_usd: float | None = None,
        cache_read_input_tokens: int = 0,
        cache_creation_input_tokens: int = 0,
    ) -> None:
        # Per-call cost / cache telemetry — needed to reconcile the
        # locally-computed ledger against the provider-billed ground
        # truth (OpenRouter ``usage.cost`` / Anthropic cache fields).
        # Optional fields default to None / 0 so existing event
        # consumers that don't know about them keep working.
        self._emit("llm_call", {
            "iteration": iteration,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "duration": round(duration, 2),
            "has_tool_calls": has_tool_calls,
            "reasoning_preview": reasoning[:200] if reasoning else None,
            "upstream_cost_usd": upstream_cost_usd,
            "cache_read_input_tokens": cache_read_input_tokens,
            "cache_creation_input_tokens": cache_creation_input_tokens,
        })

    def tool_call(
        self,
        iteration: int,
        tool_name: str,
        command: str | None,
        result_length: int,
        duration: float,
        result_preview: str | None = None,
    ) -> None:
        self._emit("tool_call", {
            "iteration": iteration,
            "tool": tool_name,
            "command": command[:200] if command else None,
            "result_length": result_length,
            "duration": round(duration, 2),
            "result_preview": result_preview[:300] if result_preview else None,
        })

    def flag_detected(self, iteration: int, flag: str, source: str) -> None:
        self._emit("flag_detected", {
            "iteration": iteration,
            "flag": flag,
            "source": source,
        })

    def loop_detected(self, iteration: int, nudge_number: int) -> None:
        self._emit("loop_detected", {
            "iteration": iteration,
            "nudge_number": nudge_number,
        })

    def stuck_recovery_nudge(self, iteration: int, remaining_iterations: int) -> None:
        """ orchestrator injected a try-harder message because the
        solver returned no tool calls but iteration budget remained."""
        self._emit("stuck_recovery_nudge", {
            "iteration": iteration,
            "remaining_iterations": remaining_iterations,
        })

    def stagnation_nudge(
        self,
        iteration: int,
        reason: str,
        nudge_number: int,
    ) -> None:
        """ orchestrator injected a tactic-change message because
        the solver appeared stuck repeating the same command/output."""
        self._emit("stagnation_nudge", {
            "iteration": iteration,
            "reason": reason,
            "nudge_number": nudge_number,
        })

    def scan_end(
        self,
        success: bool,
        iterations: int,
        flag: str | None,
        total_time: float,
        input_tokens: int,
        output_tokens: int,
        tool_calls: int,
        error: str | None = None,
    ) -> None:
        self._emit("scan_end", {
            "success": success,
            "iterations": iterations,
            "flag": flag[:20] + "..." if flag else None,
            "total_time": round(total_time, 2),
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "tool_calls": tool_calls,
            "error": error,
        })

    @property
    def events(self) -> list[dict]:
        return self._events
