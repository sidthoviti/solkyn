"""SingleLoopCompactSolver — .

Extends :class:`SingleLoopSolver` with conversation compaction. When the
estimated token count of ``self.messages`` crosses ``compaction_threshold_pct``
of the model's context window, the oldest tool-call / tool-result pairs are
summarised into one synthetic assistant message — preserving:

* the system prompt (messages[0]),
* the last ``preserve_tail_messages`` messages (default 8 ≈ 4 LLM turns),
* any message whose content matches the flag-shaped regex.

This addresses the Phase 5 death-spiral on XBEN-030-24 where a 3.2M-token
conversation accumulated and the run aborted on context-window overflow.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from solkyn.agents.flag_detector import FlagDetector
from solkyn.agents.solvers.single_loop import SingleLoopSolver
from solkyn.llm.manager import LLMManager

logger = logging.getLogger(__name__)


# Conservative default — most modern models (GPT-4o, Claude 3.5, Gemini 1.5)
# advertise ≥128K context; some go higher. We default low and let callers
# override via the constructor when they know better.
_DEFAULT_CONTEXT_WINDOW = 128_000

# Standard CTF/XBOW flag pattern. Same shape as FlagDetector but used here
# as a string regex to scan arbitrary message content. Conservative — we
# never want to compact a message containing a real flag.
_FLAG_REGEX = re.compile(r"(FLAG\{[^}]+\}|flag\{[^}]+\})", re.IGNORECASE)


def _estimate_tokens(messages: list[dict[str, Any]]) -> int:
    """Estimate token count via the well-known 4-chars-per-token heuristic
    over JSON-serialised messages. Cheap, deterministic, model-agnostic."""
    try:
        return sum(len(json.dumps(m, default=str)) for m in messages) // 4
    except Exception:
        # Defensive: any non-serialisable content falls back to str().
        return sum(len(str(m)) for m in messages) // 4


def _contains_flag(msg: dict[str, Any]) -> bool:
    """True if the message content (string or list-of-parts) contains a
    flag-shaped substring. Tool-call args are also checked."""
    content = msg.get("content")
    if isinstance(content, str) and _FLAG_REGEX.search(content):
        return True
    if isinstance(content, list):
        for part in content:
            text = part.get("text", "") if isinstance(part, dict) else str(part)
            if _FLAG_REGEX.search(text):
                return True
    # Tool calls embedded on assistant messages.
    for tc in msg.get("tool_calls") or []:
        args = tc.get("arguments") or tc.get("function", {}).get("arguments", "")
        if _FLAG_REGEX.search(str(args)):
            return True
    return False


class SingleLoopCompactSolver(SingleLoopSolver):
    """SingleLoopSolver + threshold-triggered conversation compaction."""

    def __init__(
        self,
        llm_manager: LLMManager,
        tool_schemas: list[dict] | None,
        flag_detector: FlagDetector | None = None,
        tags: list[str] | None = None,
        max_nudges: int = 3,
        *,
        compaction_threshold_pct: float = 0.7,
        model_context_window: int = _DEFAULT_CONTEXT_WINDOW,
        preserve_tail_messages: int = 8,
        summariser_llm: LLMManager | None = None,
    ):
        super().__init__(
            llm_manager=llm_manager,
            tool_schemas=tool_schemas,
            flag_detector=flag_detector,
            tags=tags,
            max_nudges=max_nudges,
        )
        if not 0.0 < compaction_threshold_pct < 1.0:
            raise ValueError("compaction_threshold_pct must be in (0, 1)")
        if model_context_window <= 0:
            raise ValueError("model_context_window must be positive")
        if preserve_tail_messages < 2:
            raise ValueError("preserve_tail_messages must be ≥ 2")
        self._threshold_pct = compaction_threshold_pct
        self._ctx_window = model_context_window
        self._preserve_tail = preserve_tail_messages
        # Optional separate summariser LLM. Defaults to the solver's LLM
        # so single-model deployments work without extra config.
        self._summariser = summariser_llm or llm_manager
        self.compaction_count = 0
        self.last_compaction_estimate: tuple[int, int] | None = None  # (before, after)

    # ------------------------------------------------------------------
    # BaseSolver override
    # ------------------------------------------------------------------

    def get_next_action(self):
        # Compact BEFORE the LLM call so the next round-trip stays under
        # the budget. Skip if there are pending tool calls in flight (we
        # must keep the assistant message that issued them intact for the
        # next tool-result append to attach to).
        if not self._pending_tool_calls:
            self._maybe_compact()
        return super().get_next_action()

    # ------------------------------------------------------------------
    # Compaction
    # ------------------------------------------------------------------

    def _threshold_tokens(self) -> int:
        return int(self._ctx_window * self._threshold_pct)

    def _maybe_compact(self) -> bool:
        """Compact if over threshold. Returns True iff compaction ran."""
        before = _estimate_tokens(self.messages)
        if before < self._threshold_tokens():
            return False
        if len(self.messages) <= self._preserve_tail + 1:
            # Nothing to coalesce — every message is in the preserved set.
            return False
        new_messages = self._compact()
        after = _estimate_tokens(new_messages)
        self.last_compaction_estimate = (before, after)
        self.compaction_count += 1
        logger.info(
            "Compaction #%d: %d → %d est. tokens (%d → %d messages)",
            self.compaction_count, before, after,
            len(self.messages), len(new_messages),
        )
        self.messages = new_messages
        return True

    def _compact(self) -> list[dict[str, Any]]:
        """Build the compacted message list.

        Layout:
            [system, ...preserved-flag-messages..., synthetic-summary,
             ...last preserve_tail messages...]
        """
        if not self.messages:
            return self.messages

        system_msg = self.messages[0]
        tail_start = max(1, len(self.messages) - self._preserve_tail)
        tail = self.messages[tail_start:]
        middle = self.messages[1:tail_start]

        # Pull out flag-bearing messages from the middle — they're never
        # compacted away. Keep them in original order.
        flag_msgs = [m for m in middle if _contains_flag(m)]
        compactable = [m for m in middle if not _contains_flag(m)]

        if not compactable:
            return self.messages  # Nothing left to summarise

        synthetic = self._summarise_block(compactable)

        return [system_msg, *flag_msgs, synthetic, *tail]

    def _summarise_block(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        """Ask the summariser LLM to compress ``messages`` into one assistant
        message. Falls back to a deterministic stub on LLM failure so the
        loop keeps running (a degraded summary beats a crashed run)."""
        try:
            transcript_lines: list[str] = []
            for m in messages:
                role = m.get("role", "?")
                content = m.get("content", "") or ""
                if isinstance(content, list):
                    content = " ".join(
                        p.get("text", "") if isinstance(p, dict) else str(p)
                        for p in content
                    )
                if len(content) > 2000:
                    content = content[:2000] + "...[truncated]"
                tcs = m.get("tool_calls") or []
                if tcs:
                    tc_str = "; ".join(
                        f"{tc.get('name', '?')}({str(tc.get('arguments', ''))[:120]})"
                        for tc in tcs
                    )
                    content = f"{content}\n→ {tc_str}"
                transcript_lines.append(f"[{role}] {content}")
            prompt = (
                "Summarise the following pentest agent conversation segment into "
                "a SHORT (max ~400 words) assistant-perspective recap. Capture: "
                "what was tried, what worked, what failed, current best lead. "
                "Cite specific endpoints/params/payloads. No preamble.\n\n"
                + "\n\n".join(transcript_lines)
            )
            response = self._summariser.chat(
                [
                    {"role": "system", "content": "You compact pentest traces."},
                    {"role": "user", "content": prompt},
                ],
                tools=None,
            )
            body = (response.get("content") or "").strip()
            if not body:
                raise RuntimeError("empty summary")
            summary_text = body
        except Exception as e:
            logger.warning("Summariser failed (%s) — using stub summary", e)
            summary_text = (
                f"[Compacted {len(messages)} prior messages — summariser unavailable.]"
            )
        return {
            "role": "assistant",
            "content": (
                "## Conversation Summary (compacted)\n\n"
                f"{summary_text}\n\n"
                "_End of compaction. Tool-using turns continue below._"
            ),
        }
