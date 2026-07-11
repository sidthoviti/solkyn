"""HackSynthSolver — planner + summarizer dual-LLM solver.

Implements the HackSynth pattern from arXiv:2412.01778 against the
:class:`BaseSolver` contract:

* The **planner** LLM sees `system_prompt + initial_user_message +
  rolling_summary + last_raw_turn` (the immediately preceding command
  + raw output, so it has at least one full turn of context). It emits
  one bash command inside ``<command>...</command>`` tags, or submits
  the captured flag inside ``<flag>...</flag>``.
* The orchestrator executes the command via the existing ``bash_exec``
  tool path — we synthesise a tool_call so the orchestrator's dispatch
  stays unchanged.
* The **summarizer** LLM compresses ``(planner_reasoning, command,
  output)`` into a 1–3 line entry that is appended to the rolling
  working memory shown to the planner on the next turn.

The planner never sees raw outputs of *past* turns — only the rolling
summary plus the most recent raw exchange. This is the key context-
saving mechanism HackSynth introduces.

Two ``LLMManager`` handles let callers pick a stronger model for the
planner and a cheaper one for the summarizer; if ``summarizer_llm`` is
``None`` the planner LLM is reused for both.

Trace format: nested per-turn (see :meth:`serialize_conversation`) with
each turn carrying both agents' message slices plus the execution result.
A flat-ified ``self.messages`` view is also maintained for backwards
compatibility with infrastructure that drains a ``solver.messages``
attribute (orchestrator state log, ``write_conversation_json``).
"""

from __future__ import annotations

import logging
import re
import uuid
from pathlib import Path
from typing import Any

from solkyn.agents.flag_detector import FlagDetector
from solkyn.agents.solvers.base import BaseSolver, SolverAction
from solkyn.llm.manager import LLMManager

logger = logging.getLogger(__name__)


_PROMPT_DIR = Path(__file__).resolve().parent.parent / "prompts" / "solvers"
_PLANNER_PROMPT_PATH = _PROMPT_DIR / "hacksynth_planner.md"
_SUMMARIZER_PROMPT_PATH = _PROMPT_DIR / "hacksynth_summarizer.md"

_COMMAND_RE = re.compile(r"<command>\s*(.*?)\s*</command>", re.DOTALL | re.IGNORECASE)
_FLAG_TAG_RE = re.compile(r"<flag>\s*(.*?)\s*</flag>", re.DOTALL | re.IGNORECASE)
_REASONING_RE = re.compile(r"<reasoning>\s*(.*?)\s*</reasoning>", re.DOTALL | re.IGNORECASE)


def _load_prompt(path: Path) -> str:
    """Read a prompt file. Raises FileNotFoundError if it's missing —
    the planner/summarizer prompts are required, not optional."""
    return path.read_text(encoding="utf-8")


class HackSynthSolver(BaseSolver):
    """HackSynth-style planner + summarizer dual-agent solver."""

    def __init__(
        self,
        planner_llm: LLMManager,
        summarizer_llm: LLMManager | None = None,
        flag_detector: FlagDetector | None = None,
        tags: list[str] | None = None,
        *,
        planner_prompt_path: Path | None = None,
        summarizer_prompt_path: Path | None = None,
        max_summary_chars: int = 8_000,
        max_raw_output_in_planner_view: int = 6_000,
    ):
        self._planner = planner_llm
        self._summarizer = summarizer_llm or planner_llm
        self.flag_detector = flag_detector or FlagDetector()
        self._tags = tags
        self._planner_prompt = _load_prompt(planner_prompt_path or _PLANNER_PROMPT_PATH)
        self._summarizer_prompt = _load_prompt(
            summarizer_prompt_path or _SUMMARIZER_PROMPT_PATH
        )
        self._max_summary_chars = max_summary_chars
        self._max_raw_in_view = max_raw_output_in_planner_view

        # State seeded by initialize() / inject_message().
        self._base_system_prompt: str = ""
        self._initial_user_message: str = ""

        # Rolling summary entries — list of strings, oldest-first. Re-rendered
        # into the planner view as a numbered list each turn.
        self._summary_entries: list[str] = []

        # Last raw exchange the planner is allowed to see verbatim.
        self._last_raw_command: str | None = None
        self._last_raw_output: str | None = None
        self._last_planner_reasoning: str | None = None

        # Pending action awaiting handle_result, so summariser can compose
        # the right summary entry. Captures the planner's reasoning and the
        # command it issued.
        self._pending_action: dict[str, Any] | None = None

        # Per-turn nested trace ( contract).
        self._turns: list[dict[str, Any]] = []
        self._current_turn: dict[str, Any] | None = None

        # Iteration counter — one planner call = one iteration.
        self._iteration_count = 0

        # Cached usage from the most recent planner call (orchestrator reads).
        self._last_llm_usage: dict[str, int] = {"input_tokens": 0, "output_tokens": 0}

        # Flat back-compat view — interleaved synthetic messages so legacy
        # consumers (orchestrator state-log drain, write_conversation_json)
        # see something useful even though our canonical trace is nested.
        self.messages: list[dict[str, Any]] = []

        # Last detected flag in planner text — for orchestrator inspection.
        self._last_flag_in_text: str | None = None

    # ------------------------------------------------------------------
    # BaseSolver contract
    # ------------------------------------------------------------------

    def initialize(self, system_prompt: str) -> None:
        """Seed the planner's base system prompt.

        We append the HackSynth planner contract on every planner call so
        that what we keep here is exactly what the orchestrator handed us
        (the standard solver_system + playbooks + canary)."""
        self._base_system_prompt = system_prompt
        self.messages = [{"role": "system", "content": system_prompt}]

    def inject_message(self, role: str, content: str) -> None:
        """Capture the orchestrator's initial user message (target + tags
        + source files in whitebox mode). Subsequent injects (e.g. from
        a stuck-handling nudge) are also captured so they show up in the
        flat back-compat view, but only the first ``user`` message is
        forwarded into every planner call."""
        if role == "user" and not self._initial_user_message:
            self._initial_user_message = content
        self.messages.append({"role": role, "content": content})

    def get_iteration_count(self) -> int:
        return self._iteration_count

    def serialize_conversation(self) -> dict[str, Any]:
        """Nested per-turn trace.

        Each turn contains:

        * ``turn``: 1-based turn index.
        * ``agents``: list of ``{name, messages, usage}`` dicts; for
          HackSynth this is ``[planner, summarizer]``.
        * ``execution``: ``{command, output, summary_entry}`` — the
          shell exchange the orchestrator performed and the summary the
          summarizer produced from it. ``execution`` may be ``None`` for
          the final turn if it ended with a flag submission.
        """
        return {
            "format": "nested",
            "turns": list(self._turns),
            "rolling_summary": list(self._summary_entries),
        }

    def get_next_action(self) -> SolverAction:
        # Build planner prompt: base system + planner-mode appendix.
        planner_messages = self._build_planner_messages()

        # Call planner — no tools; pure text completion.
        response = self._planner.chat(planner_messages, tools=None)
        self._iteration_count += 1
        self._last_llm_usage = response.get("usage") or {
            "input_tokens": 0,
            "output_tokens": 0,
        }
        text = response.get("content") or ""

        # Open a new turn in the nested trace + record the planner agent.
        self._current_turn = {
            "turn": self._iteration_count,
            "agents": [
                {
                    "name": "planner",
                    "messages": planner_messages,
                    "response": text,
                    "usage": self._last_llm_usage,
                }
            ],
            "execution": None,
        }

        # Append a synthetic assistant message into the flat view so
        # solver.jsonl + conversation.json show what the planner said.
        self.messages.append({"role": "assistant", "content": text})

        # Surface flag-shape hits in planner text to the orchestrator.
        self._last_flag_in_text = None
        if text:
            detected = self.flag_detector.scan(text)
            if detected:
                self._last_flag_in_text = detected[0]

        # Did the planner submit a flag via <flag>...</flag>?
        flag_match = _FLAG_TAG_RE.search(text)
        if flag_match:
            flag = flag_match.group(1).strip()
            self._turns.append(self._current_turn)
            self._current_turn = None
            return SolverAction(
                type="flag",
                flag=flag,
                reasoning=self._extract_reasoning(text),
                metadata={
                    "is_new_iteration": True,
                    "usage": self._last_llm_usage,
                    "flag_in_text": self._last_flag_in_text,
                },
            )

        # Did the planner emit <command>...</command>?
        cmd_match = _COMMAND_RE.search(text)
        if not cmd_match:
            # Malformed turn — close it out and signal to the orchestrator.
            self._turns.append(self._current_turn)
            self._current_turn = None
            logger.warning(
                "Planner returned no <command> or <flag> tag (text len=%d) — terminating",
                len(text),
            )
            return SolverAction(
                type="none",
                reasoning=text,
                metadata={
                    "is_new_iteration": True,
                    "continue_loop": False,
                    "usage": self._last_llm_usage,
                    "flag_in_text": self._last_flag_in_text,
                    "malformed": True,
                },
            )

        command = cmd_match.group(1).strip()
        reasoning = self._extract_reasoning(text)

        # Stash for the summariser to consume in handle_result.
        self._pending_action = {
            "command": command,
            "reasoning": reasoning,
        }

        # Synthesise a tool_call_id so the orchestrator's bash_exec
        # dispatch path works unchanged.
        tool_call_id = f"hsh-{uuid.uuid4().hex[:12]}"
        return SolverAction(
            type="command",
            tool_name="bash_exec",
            tool_args={"command": command},
            tool_call_id=tool_call_id,
            reasoning=reasoning,
            metadata={
                "is_new_iteration": True,
                "usage": self._last_llm_usage,
                "flag_in_text": self._last_flag_in_text,
                "batch_size": 1,
            },
        )

    def handle_result(self, result: dict[str, Any]) -> None:
        """Receive the executor's output for the planner's command, then
        run the summarizer to compress it into one rolling-summary entry.

        Expected ``result`` keys: ``output`` (str), ``tool_call_id``,
        ``tool_name``. Other keys (``exit_code``, ``stdout``, ``stderr``,
        ``timed_out``) are tolerated but optional."""
        output = result.get("output", "")
        if self._pending_action is None:
            logger.warning(
                "handle_result called without a pending action — ignoring (output len=%d)",
                len(output),
            )
            return

        command = self._pending_action["command"]
        reasoning = self._pending_action["reasoning"]
        self._pending_action = None
        self._last_planner_reasoning = reasoning

        # Run the summariser.
        summarizer_messages = self._build_summarizer_messages(
            reasoning=reasoning, command=command, output=output,
        )
        summarizer_response = self._summarizer.chat(summarizer_messages, tools=None)
        summary_text = (summarizer_response.get("content") or "").strip()
        if not summary_text:
            # Fall back to a deterministic stub so the planner still gets
            # *some* signal next turn — better than total amnesia.
            summary_text = (
                f"[summary missing] ran `{command[:80]}` → {len(output)} chars output"
            )
        summarizer_usage = summarizer_response.get("usage") or {
            "input_tokens": 0, "output_tokens": 0,
        }

        # Append entry + apply the rolling cap (oldest dropped first).
        self._summary_entries.append(summary_text)
        self._enforce_summary_cap()

        # Update the "last raw turn" the planner sees verbatim next round.
        self._last_raw_command = command
        self._last_raw_output = output

        # Close the current nested-trace turn.
        if self._current_turn is not None:
            self._current_turn["agents"].append(
                {
                    "name": "summarizer",
                    "messages": summarizer_messages,
                    "response": summary_text,
                    "usage": summarizer_usage,
                }
            )
            self._current_turn["execution"] = {
                "command": command,
                "output": output,
                "summary_entry": summary_text,
            }
            self._turns.append(self._current_turn)
            self._current_turn = None

        # Append flat back-compat tool-result message.
        self.messages.append(
            {"role": "tool", "content": output, "name": "bash_exec",
             "tool_call_id": result.get("tool_call_id")},
        )
        self.messages.append(
            {"role": "system", "content": f"[summary] {summary_text}"},
        )

    # ------------------------------------------------------------------
    # Optional orchestrator hooks
    # ------------------------------------------------------------------

    @property
    def last_llm_usage(self) -> dict[str, int]:
        return self._last_llm_usage

    @property
    def last_flag_in_text(self) -> str | None:
        return self._last_flag_in_text

    def set_iteration_hint(
        self,
        iterations_remaining: int,  # noqa: ARG002 — accepted for API parity
        flag_already_found: bool = False,  # noqa: ARG002
    ) -> None:
        """No-op hint receiver. HackSynth doesn't gate on iters-remaining
        the way SingleLoopSolver does; we accept the hint to stay drop-in
        compatible with the orchestrator surface."""
        return None

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _build_planner_messages(self) -> list[dict[str, Any]]:
        """Assemble the planner's per-turn message list.

        Layout: ``system`` (base + planner-mode appendix) → ``user``
        (initial target context) → ``user`` (rolling summary +
        last raw turn). The third message is rebuilt every call so the
        planner always sees the freshest summary state, but past planner
        turns are NOT included — that's the whole point of the
        summarizer."""
        sys_content = (
            self._base_system_prompt + "\n\n" + self._planner_prompt
        )
        msgs: list[dict[str, Any]] = [{"role": "system", "content": sys_content}]
        if self._initial_user_message:
            msgs.append({"role": "user", "content": self._initial_user_message})

        view_parts: list[str] = []
        if self._summary_entries:
            view_parts.append("## Rolling Working Memory")
            view_parts.append(
                "Each entry is a 1–3 line summary of one prior turn, oldest first. "
                "These are the only artefacts surviving from past turns."
            )
            for i, entry in enumerate(self._summary_entries, start=1):
                view_parts.append(f"{i}. {entry}")
        else:
            view_parts.append("## Rolling Working Memory")
            view_parts.append("(empty — this is your first turn)")

        if self._last_raw_command is not None:
            view_parts.append("\n## Last Turn (raw)")
            view_parts.append(f"```bash\n{self._last_raw_command}\n```")
            raw = self._last_raw_output or ""
            if len(raw) > self._max_raw_in_view:
                raw = (
                    raw[: self._max_raw_in_view]
                    + f"\n\n…[truncated {len(raw) - self._max_raw_in_view} chars]"
                )
            view_parts.append(f"Output:\n```\n{raw}\n```")

        view_parts.append("\n## Your Turn")
        view_parts.append(
            "Emit exactly one `<command>…</command>` (or `<flag>…</flag>` if you "
            "have it) per the planner protocol above."
        )
        msgs.append({"role": "user", "content": "\n".join(view_parts)})
        return msgs

    def _build_summarizer_messages(
        self, *, reasoning: str | None, command: str, output: str,
    ) -> list[dict[str, Any]]:
        """Build the summarizer's prompt. Cheap, totally stateless — we
        rebuild it every call from scratch."""
        body_lines = [
            "## Planner reasoning",
            reasoning.strip() if reasoning else "(none)",
            "",
            "## Command issued",
            f"```bash\n{command}\n```",
            "",
            "## Raw output",
            f"```\n{output}\n```",
            "",
            "Produce the 1–3 line summary now per the contract above.",
        ]
        return [
            {"role": "system", "content": self._summarizer_prompt},
            {"role": "user", "content": "\n".join(body_lines)},
        ]

    def _enforce_summary_cap(self) -> None:
        """Drop oldest entries if the cumulative summary text exceeds
        ``max_summary_chars``. We never drop fewer than 1 entry."""
        while self._summary_entries:
            total = sum(len(e) for e in self._summary_entries)
            if total <= self._max_summary_chars:
                return
            dropped = self._summary_entries.pop(0)
            logger.info("Rolling summary at cap — dropped oldest entry (%d chars)",
                        len(dropped))

    @staticmethod
    def _extract_reasoning(text: str) -> str | None:
        m = _REASONING_RE.search(text)
        if m:
            return m.group(1).strip()
        return None
