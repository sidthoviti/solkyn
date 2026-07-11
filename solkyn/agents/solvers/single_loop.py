"""SingleLoopSolver — the original Solkyn loop strategy, extracted as a
:class:`BaseSolver` implementation.

Owns:
* Conversation history (``messages``) and message append helpers.
* LLM dispatch (`get_next_action` calls ``llm.chat``).
* Multi-tool-call queuing (one LLM response can produce N parallel tool
  calls; orchestrator processes one at a time but the iteration counter
  only ticks per LLM call).
* Loop detection.
* Tag-aware nudge text generation (delegated to ``_nudges``).
* Continuation nudge when the model returns no tool calls but iterations
  + nudge budget remain.
"""

from __future__ import annotations

import logging
from typing import Any

from solkyn.agents.flag_detector import FlagDetector
from solkyn.agents.solvers._nudges import (
    CONTINUATION_NUDGE,
    build_loop_nudge,
    classify_tags,
)
from solkyn.agents.solvers.base import BaseSolver, SolverAction
from solkyn.llm.manager import LLMManager
from solkyn.llm.tools import build_assistant_message_with_tool_calls, build_tool_result_message

logger = logging.getLogger(__name__)


class SingleLoopSolver(BaseSolver):
    """Single-LLM, tool-calling solver — current production strategy."""

    def __init__(
        self,
        llm_manager: LLMManager,
        tool_schemas: list[dict] | None,
        flag_detector: FlagDetector | None = None,
        tags: list[str] | None = None,
        max_nudges: int = 3,
    ):
        self.llm = llm_manager
        self.tool_schemas = tool_schemas
        self.flag_detector = flag_detector or FlagDetector()
        self.tags = tags
        self.max_nudges = max_nudges

        # Conversation state
        self.messages: list[dict] = []

        # Loop detection state
        self.recent_commands: list[str] = []
        self.recent_results: list[str] = []
        self.nudge_count = 0

        # One iteration is one LLM call.
        self._iteration_count = 0

        # Multi-tool-call queue from current LLM response
        self._pending_tool_calls: list[dict] = []
        self._last_response: dict | None = None

        # Orchestrator hints for continuation-nudge injection.
        self._iterations_remaining_hint: int | None = None
        self._flag_already_found_hint: bool = False

        # Per-batch flag detected in LLM text (orchestrator can read after action)
        self._last_flag_in_text: str | None = None
        self._last_llm_usage: dict = {"input_tokens": 0, "output_tokens": 0}

    # ------------------------------------------------------------------
    # BaseSolver contract
    # ------------------------------------------------------------------

    def initialize(self, system_prompt: str) -> None:
        """Seed conversation with the system prompt.

        The orchestrator should also call :meth:`inject_message` with the
        initial user message (target description) before the loop begins,
        so we keep two distinct calls rather than overload this one.
        """
        self.messages = [{"role": "system", "content": system_prompt}]

    def inject_message(self, role: str, content: str) -> None:
        """Append a message to the conversation (used for initial user msg
        and orchestrator-driven nudges)."""
        self.messages.append({"role": role, "content": content})

    def get_iteration_count(self) -> int:
        return self._iteration_count

    def serialize_conversation(self) -> dict[str, Any]:
        return {"format": "flat", "messages": list(self.messages)}

    def get_next_action(self) -> SolverAction:
        # Drain pending parallel tool calls from the previous LLM response.
        if self._pending_tool_calls:
            tc = self._pending_tool_calls.pop(0)
            return SolverAction(
                type="command",
                tool_name=tc["name"],
                tool_args=tc["arguments"],
                tool_call_id=tc["id"],
                metadata={"is_new_iteration": False},
            )

        # Otherwise ask the LLM for the next batch.
        response = self.llm.chat(
            self.messages,
            tools=self.tool_schemas if self.tool_schemas else None,
        )
        self._iteration_count += 1
        self._last_response = response

        content = response.get("content")
        tool_calls = response.get("tool_calls")
        usage = response.get("usage", {})
        self._last_llm_usage = usage

        # Detect flag in LLM text (orchestrator surfaces this).
        self._last_flag_in_text = None
        if content:
            detected = self.flag_detector.scan(content)
            if detected:
                self._last_flag_in_text = detected[0]

        # No tool calls → either inject continuation nudge or terminate.
        # Only nudge when no flag has been verified yet,
        # at least 2 iterations remain, and nudge budget is not exhausted.
        # Also: if THIS response contains a flag in its text, don't nudge —
        # orchestrator will record it and break.
        if not tool_calls:
            iters_left = self._iterations_remaining_hint or 0
            should_nudge = (
                iters_left >= 2
                and self.nudge_count < self.max_nudges
                and not self._flag_already_found_hint
                and not self._last_flag_in_text
            )
            if should_nudge:
                self.nudge_count += 1
                logger.info(
                    "Agent returned no tool calls — injecting continuation nudge #%d",
                    self.nudge_count,
                )
                self.messages.append({"role": "assistant", "content": content or ""})
                self.messages.append({"role": "user", "content": CONTINUATION_NUDGE})
                return SolverAction(
                    type="none",
                    reasoning=content,
                    metadata={
                        "is_new_iteration": True,
                        "continue_loop": True,
                        "injected_continuation_nudge": True,
                        "usage": usage,
                        "flag_in_text": self._last_flag_in_text,
                    },
                )

            # Terminate.
            self.messages.append({"role": "assistant", "content": content or ""})
            return SolverAction(
                type="none",
                reasoning=content,
                metadata={
                    "is_new_iteration": True,
                    "continue_loop": False,
                    "usage": usage,
                    "flag_in_text": self._last_flag_in_text,
                },
            )

        # Has tool calls — append assistant msg, queue all but the first.
        assistant_msg = build_assistant_message_with_tool_calls(content, tool_calls)
        self.messages.append(assistant_msg)
        self._pending_tool_calls = list(tool_calls)
        first = self._pending_tool_calls.pop(0)
        return SolverAction(
            type="command",
            tool_name=first["name"],
            tool_args=first["arguments"],
            tool_call_id=first["id"],
            reasoning=content,
            metadata={
                "is_new_iteration": True,
                "usage": usage,
                "flag_in_text": self._last_flag_in_text,
                "batch_size": len(tool_calls),
            },
        )

    def handle_result(self, result: dict[str, Any]) -> None:
        """Append tool result, update loop-detection state.

        Expected ``result`` keys:
        * ``tool_call_id`` — match to assistant msg
        * ``tool_name``, ``tool_args`` — for loop signature
        * ``output`` — full tool output string

        After the LAST tool call in this iteration's batch (i.e. the
        pending queue is empty), check for loop-detection and inject a
        nudge if triggered.
        """
        tc_id = result["tool_call_id"]
        tool_name = result["tool_name"]
        tool_args = result.get("tool_args", {})
        output = result["output"]

        self.messages.append(build_tool_result_message(tc_id, output))

        # Loop-detection signals
        cmd_sig = self._normalize_command_sig(tool_name, tool_args)
        self.recent_commands.append(cmd_sig)
        self.recent_results.append(output[:200])

        # Only check for loops at the end of a tool-call batch.
        # after all tool calls of one LLM response are processed).
        if not self._pending_tool_calls:
            self._maybe_inject_loop_nudge()

    # ------------------------------------------------------------------
    # Orchestrator helpers (not part of BaseSolver contract)
    # ------------------------------------------------------------------

    def set_iteration_hint(
        self,
        iterations_remaining: int,
        flag_already_found: bool = False,
    ) -> None:
        """Orchestrator informs the solver of iterations-remaining and whether
        a flag has already been verified this run.

        Both gate continuation-nudge injection:
        nudge only when no flag found yet, at least 2 iterations remain).
        """
        self._iterations_remaining_hint = iterations_remaining
        self._flag_already_found_hint = flag_already_found

    @property
    def last_llm_usage(self) -> dict:
        return self._last_llm_usage

    @property
    def last_flag_in_text(self) -> str | None:
        return self._last_flag_in_text

    # ------------------------------------------------------------------
    # Internal — loop-detection + nudges
    # ------------------------------------------------------------------

    def _maybe_inject_loop_nudge(self) -> bool:
        loop_detected = False

        # Strategy 1: last 4 commands have ≤2 unique signatures
        if len(self.recent_commands) >= 4:
            last_four = self.recent_commands[-4:]
            if len(set(last_four)) <= 2:
                loop_detected = True

        # Strategy 2: last 6 commands have ≤3 unique (catches interleaved loops)
        if not loop_detected and len(self.recent_commands) >= 6:
            last_six = self.recent_commands[-6:]
            if len(set(last_six)) <= 3:
                loop_detected = True

        # Strategy 3: last 3 tool outputs identical (and non-empty)
        if not loop_detected and len(self.recent_results) >= 3:
            last_three = self.recent_results[-3:]
            if len(set(last_three)) == 1 and last_three[0]:
                loop_detected = True

        if not loop_detected:
            return False

        self.nudge_count += 1
        logger.warning("Loop detected (nudge #%d) — injecting correction", self.nudge_count)
        category = classify_tags(self.tags)
        nudge_text = build_loop_nudge(category, self.nudge_count)
        self.messages.append({"role": "user", "content": nudge_text})
        self.recent_commands.clear()
        return True

    @staticmethod
    def _normalize_command_sig(tool_name: str, args: dict) -> str:
        """Normalize a shell command for loop detection."""
        if tool_name == "bash_exec":
            cmd = args.get("command", "")
            base_cmd = cmd.strip().split()[0] if cmd.strip() else "empty"
            if base_cmd == "curl" and "-X POST" in cmd:
                return "bash_exec:curl_post"
            if base_cmd == "python3" or base_cmd == "python":
                return "bash_exec:python"
            return f"bash_exec:{base_cmd}"
        return f"{tool_name}:{str(args)[:80]}"
