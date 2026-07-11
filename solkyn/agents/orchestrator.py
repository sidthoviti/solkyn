"""Orchestrator — strategy-agnostic solver loop runner.

Owns the outer `while True` loop, iteration limit checks, executor
dispatch, flag scanning of tool outputs, per-iteration state save, and
display/event hooks. Delegates the "what to do next" decision entirely
to a `BaseSolver` implementation.

Extracted from `SolverAgent.run()` in . Behaviour is identical to
the previous inline loop; this file only relocates code.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Literal

from solkyn.agents.flag_detector import FlagDetector
from solkyn.agents.solvers.base import BaseSolver
from solkyn.agents.state import ScanState
from solkyn.core.cost import CostTracker
from solkyn.core.deadline import Deadline
from solkyn.observability.display import RunDisplay
from solkyn.observability.events import EventLogger
from solkyn.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)


ExitReason = Literal[
    "flag_found",
    "max_iterations",
    "no_tool_calls",
    "time_limit",
    "cost_limit",
    "error",
]


@dataclass
class OrchestratorResult:
    """Result returned by `Orchestrator.run`.

    The caller (currently `SolverAgent.run`) is responsible for assembling
    the final `AgentResult` from this plus token usage, screenshots, and
    timing — the orchestrator stays free of presentation concerns.
    """

    flags_found: list[str] = field(default_factory=list)
    iterations: int = 0
    tool_calls_log: list[dict[str, Any]] = field(default_factory=list)
    exit_reason: ExitReason = "no_tool_calls"
    error: str | None = None
    #  set True when stuck-handling actually injected a try-harder
    # message during the run. Surfaced for reporting/observability so we
    # can later quantify how often the nudge fires and whether it correlates
    # with a downstream solve.
    stuck_recovery_used: bool = False
    #  number of tactic-change nudges injected during the run when
    # the solver appeared stuck repeating the same command/output. Capped
    # at ``Orchestrator._MAX_STAGNATION_NUDGES`` to avoid prompt spam.
    stagnation_nudges_used: int = 0


#  Stuck-handling try-harder template. Built dynamically with the
# last command/output context (truncated) so the model has something
# concrete to react to instead of a generic "keep going" plea.
_TRY_HARDER_TEMPLATE = (
    "⚠ You returned a response with no tool calls, but the flag has not been "
    "found and you still have iteration budget remaining. Do NOT give up.\n\n"
    "Your most recent activity:\n"
    "{recent_context}\n\n"
    "Re-engage with a DIFFERENT approach. Consider:\n"
    "  - A different vulnerability class (re-read your playbooks).\n"
    "  - A different endpoint or parameter you haven't tested.\n"
    "  - A different tool (sqlmap → ffuf → nuclei → custom python).\n"
    "  - Re-reading any source files you were given for clues you missed.\n"
    "Take the next concrete action by issuing a tool call."
)


#  Stagnation tactic-change template. Kept terse (≈ 6 lines) so it
# doesn't crowd the LLM context but specific enough that the agent has
# something concrete to react to.
_STAGNATION_TEMPLATE = (
    "⚠ STAGNATION DETECTED: {reason}\n\n"
    "What you've been trying isn't working. Do NOT repeat the same command "
    "or probe the same endpoint again. Required next move:\n"
    "  - Switch to a DIFFERENT vulnerability class or technique (re-read "
    "your playbooks for ideas you skipped).\n"
    "  - Probe an endpoint or parameter you haven't touched yet.\n"
    "  - If the response keeps being identical (404, 403, empty), the path "
    "is wrong — enumerate with ffuf/dirsearch instead of guessing.\n"
    "  - If a tool keeps timing out / failing, try a different tool.\n"
    "Take ONE concrete new action."
)


def _normalise_command(tool_name: str, tool_args: dict[str, Any]) -> str:
    """Build a stable signature for a tool invocation so the stagnation
    detector can recognise a repeat regardless of incidental whitespace
    differences. We keep the tool name as a prefix so e.g. two different
    tools with identical args don't collide.
    """
    if tool_name == "bash_exec":
        cmd = str(tool_args.get("command", "")).strip()
        # Collapse runs of whitespace so "ls  -la" == "ls -la".
        cmd = " ".join(cmd.split())
        return f"bash:{cmd}"
    # For non-bash tools, use a sorted-key repr of the args dict.
    try:
        items = sorted(tool_args.items())
    except Exception:  # noqa: BLE001 — args may contain unhashable values
        items = list(tool_args.items())
    return f"{tool_name}:{items!r}"


def _result_signature(result_str: str) -> str:
    """Build a stable signature for a tool result. We use the length plus
    the first 200 chars (stripped) — enough to distinguish "404 not found"
    from "200 OK <html>..." while ignoring trivial differences (timestamps,
    request IDs) that appear later in the response.
    """
    head = result_str[:200].strip()
    return f"{len(result_str)}:{head}"


def _build_try_harder_message(tool_calls_log: list[dict[str, Any]]) -> str:
    """Build the try-harder message body, embedding the last 1–3 tool calls
    (with truncated outputs) so the LLM can ground its next attempt in
    concrete recent context rather than abstract advice."""
    if not tool_calls_log:
        recent = "  (No tool calls yet — start with reconnaissance: whatweb, curl, ffuf.)"
    else:
        recent_calls = tool_calls_log[-3:]
        lines: list[str] = []
        for call in recent_calls:
            tool = call.get("tool", "?")
            args = call.get("args", {})
            preview = call.get("args", {}).get("command", "")
            if not preview:
                preview = str(args)[:120]
            elif len(preview) > 120:
                preview = preview[:120] + "..."
            lines.append(f"  iter {call.get('iteration', '?')}: {tool}({preview})")
        recent = "\n".join(lines)
    return _TRY_HARDER_TEMPLATE.format(recent_context=recent)


class Orchestrator:
    """Strategy-agnostic loop runner over a `BaseSolver`."""

    #  stagnation detection tunables.
    # We only emit a tactic-change nudge a small number of times per run
    # to avoid prompt spam if the agent is genuinely stuck on a single
    # technique that just needs more iterations.
    _MAX_STAGNATION_NUDGES = 2
    # Number of most-recent tool calls to consider when checking for
    # repetition. With WINDOW=4 and THRESHOLD=3 we fire when 3+ of the
    # last 4 calls share an identical normalised command OR result
    # signature — i.e. the agent has burned 3 turns getting the same
    # answer or running the same probe.
    _STAGNATION_WINDOW = 4
    _STAGNATION_THRESHOLD = 3

    def __init__(
        self,
        tools: ToolRegistry,
        flag_detector: FlagDetector,
        max_iterations: int,
        display: RunDisplay | None = None,
        events: EventLogger | None = None,
        deadline: Deadline | None = None,
        cost_tracker: CostTracker | None = None,
        max_cost_usd: float | None = None,
        model_name: str | None = None,
    ) -> None:
        self.tools = tools
        self.flag_detector = flag_detector
        self.max_iterations = max_iterations
        self._display = display
        self._events = events
        self.deadline = deadline
        self.cost_tracker = cost_tracker
        self.max_cost_usd = max_cost_usd
        # Model name used to attribute usage records to the cost tracker.
        # Optional — when omitted, cost tracking is a no-op.
        self.model_name = model_name

    def run(
        self,
        solver: BaseSolver,
        scan_dir: str | None = None,
        state: ScanState | None = None,
    ) -> OrchestratorResult:
        """Drive `solver` until a flag is found, max iterations hit, or
        the solver yields a terminal `none` action.
        """
        result = OrchestratorResult()
        iteration = 0
        last_logged_msg_count = self._initial_message_count(solver, scan_dir, state)

        try:
            while True:
                # Time/cost limits checked before iteration cap so that
                # exit_reason reflects the true binding constraint.
                if self.deadline is not None and self.deadline.expired:
                    logger.info("Deadline expired — stopping")
                    result.exit_reason = "time_limit"
                    break
                if (
                    self.cost_tracker is not None
                    and self.cost_tracker.over_budget(self.max_cost_usd)
                ):
                    logger.info(
                        "Cost budget exhausted ($%.4f >= $%.4f) — stopping",
                        self.cost_tracker.total_usd, self.max_cost_usd or 0.0,
                    )
                    result.exit_reason = "cost_limit"
                    break

                # Iteration cap — solver may opt out (e.g. HackSynth).
                if (
                    not solver.should_ignore_max_iterations()
                    and iteration >= self.max_iterations
                ):
                    result.exit_reason = "max_iterations"
                    break

                # Hint: iterations remaining + flag-already-found gate.
                solver.set_iteration_hint(
                    self.max_iterations - iteration,
                    flag_already_found=bool(result.flags_found),
                )

                action = solver.get_next_action()
                is_new = bool(action.metadata.get("is_new_iteration", False))

                if is_new:
                    iteration += 1
                    self._on_new_iteration(iteration, action, state, result)

                # Persist any new messages the solver appended (system / user
                # / assistant content + LLM call).
                last_logged_msg_count = self._drain_messages(
                    solver, scan_dir, state, last_logged_msg_count,
                )

                if action.type == "none":
                    if action.metadata.get("continue_loop"):
                        # Continuation nudge already injected by solver.
                        last_logged_msg_count = self._drain_messages(
                            solver, scan_dir, state, last_logged_msg_count,
                        )
                        continue
                    # Flag may have been detected in the LLM response text on
                    # this same iteration (handled in `_on_new_iteration`); if
                    # so, prefer the more meaningful "flag_found" exit reason.
                    if result.flags_found:
                        logger.info(
                            "Flag found in iteration %d (LLM text): %s",
                            iteration, result.flags_found[0],
                        )
                        result.exit_reason = "flag_found"
                        break
                    #  stuck-handling: inject one try-harder message
                    # if we still have budget and haven't already used the
                    # nudge. Returns to top of loop for another LLM call.
                    has_budget = (
                        solver.should_ignore_max_iterations()
                        or iteration < self.max_iterations
                    )
                    if not result.stuck_recovery_used and has_budget:
                        nudge = _build_try_harder_message(result.tool_calls_log)
                        solver.inject_message("user", nudge)
                        result.stuck_recovery_used = True
                        logger.info(
                            "Stuck-handling: injected try-harder nudge after "
                            "iteration %d (no tool calls, no flag, budget remaining).",
                            iteration,
                        )
                        if self._events:
                            self._events.stuck_recovery_nudge(
                                iteration=iteration,
                                remaining_iterations=self.max_iterations - iteration,
                            )
                        last_logged_msg_count = self._drain_messages(
                            solver, scan_dir, state, last_logged_msg_count,
                        )
                        continue
                    logger.info("Agent returned no tool calls — stopping")
                    result.exit_reason = "no_tool_calls"
                    break

                if action.type == "command":
                    self._dispatch_command(
                        action, iteration, solver, state, result,
                    )
                    self._maybe_inject_stagnation_nudge(
                        iteration, solver, result,
                    )
                    last_logged_msg_count = self._drain_messages(
                        solver, scan_dir, state, last_logged_msg_count,
                    )

                if result.flags_found:
                    logger.info(
                        "Flag found after iteration %d: %s",
                        iteration, result.flags_found[0],
                    )
                    result.exit_reason = "flag_found"
                    break

                if scan_dir and state:
                    state.flags = list(set(result.flags_found))
                    state.save(scan_dir)

        except Exception as e:  # noqa: BLE001 — wrap & surface for AgentResult
            logger.error("Orchestrator error: %s", e)
            result.exit_reason = "error"
            result.error = str(e)

        result.iterations = iteration
        return result

    # ------------------------------------------------------------------
    # Helpers (private)
    # ------------------------------------------------------------------

    @staticmethod
    def _initial_message_count(
        solver: BaseSolver,
        scan_dir: str | None,
        state: ScanState | None,
    ) -> int:
        """Mirror the solver's initial messages into the state log and
        return the number of messages already persisted.
        """
        # SingleLoopSolver exposes `messages`; other solvers may not.
        # We fall back to 0 if the attribute is absent — the orchestrator
        # only persists messages it can see.
        messages = getattr(solver, "messages", None)
        if messages is None:
            return 0
        if scan_dir and state:
            for m in messages:
                state.append_log(scan_dir, m)
        return len(messages)

    @staticmethod
    def _drain_messages(
        solver: BaseSolver,
        scan_dir: str | None,
        state: ScanState | None,
        last_count: int,
    ) -> int:
        """Append every solver message added since `last_count` to the
        state log. Returns the new count.
        """
        if not (scan_dir and state):
            return last_count
        messages = getattr(solver, "messages", None)
        if messages is None:
            return last_count
        while last_count < len(messages):
            state.append_log(scan_dir, messages[last_count])
            last_count += 1
        return last_count

    def _on_new_iteration(
        self,
        iteration: int,
        action: Any,
        state: ScanState | None,
        result: OrchestratorResult,
    ) -> None:
        """Emit display+event hooks and update token counters when a fresh
        LLM call produced this action.
        """
        logger.info("=== Iteration %d/%d ===", iteration, self.max_iterations)
        if self._display:
            self._display.iteration_start(iteration, self.max_iterations)
        if self._events:
            self._events.iteration_start(iteration, self.max_iterations)
        if state:
            state.phase = "thinking"
            state.iterations = iteration
        if self._display:
            self._display.thinking()

        usage = action.metadata.get("usage", {}) or {}
        if self.cost_tracker is not None and self.model_name and usage:
            self.cost_tracker.record(self.model_name, usage)
        if self._events:
            self._events.llm_call(
                iteration=iteration,
                input_tokens=usage.get("input_tokens", 0),
                output_tokens=usage.get("output_tokens", 0),
                duration=0.0,
                has_tool_calls=action.type == "command",
                reasoning=action.reasoning,
                upstream_cost_usd=usage.get("upstream_cost_usd"),
                cache_read_input_tokens=usage.get("cache_read_input_tokens", 0),
                cache_creation_input_tokens=usage.get("cache_creation_input_tokens", 0),
            )
        if self._display and action.reasoning:
            self._display.reasoning(action.reasoning)

        flag_in_text = action.metadata.get("flag_in_text")
        if flag_in_text:
            result.flags_found.append(flag_in_text)
            logger.info("Flag detected in LLM response: %s", flag_in_text)
            if self._display:
                self._display.flag_found(flag_in_text, iteration)
            if self._events:
                self._events.flag_detected(iteration, flag_in_text, "llm_response")

        if state:
            state.token_usage["input_tokens"] += usage.get("input_tokens", 0)
            state.token_usage["output_tokens"] += usage.get("output_tokens", 0)

    def _dispatch_command(
        self,
        action: Any,
        iteration: int,
        solver: BaseSolver,
        state: ScanState | None,
        result: OrchestratorResult,
    ) -> None:
        """Execute a tool call, scan for flags, feed the result back to
        the solver, and update logs.
        """
        if state:
            state.phase = "executing"

        tc_name = action.tool_name or ""
        tc_args = action.tool_args or {}
        tc_id = action.tool_call_id or ""

        logger.info("Tool call: %s(%s)", tc_name, str(tc_args)[:200])
        if self._display:
            if tc_name == "bash_exec":
                self._display.tool_call(tc_name, command=tc_args.get("command"))
            elif tc_name in ("file_write", "file_read"):
                self._display.tool_call(tc_name, args_preview=tc_args.get("path", ""))
            else:
                self._display.tool_call(tc_name, args_preview=str(tc_args)[:100])

        tc_start = time.time()
        try:
            result_str = self.tools.execute_tool(tc_name, tc_args)
        except Exception as e:  # noqa: BLE001 — surface tool errors as text
            result_str = f"ERROR: {e}"
            logger.error("Tool execution error: %s", e)
        tc_duration = time.time() - tc_start

        log_entry = {
            "iteration": iteration,
            "tool": tc_name,
            "args": tc_args,
            "result_length": len(result_str),
            "duration": round(tc_duration, 2),
            #  signatures used by the stagnation detector. Kept on
            # the log entry so the detector stays a pure function of
            # ``result.tool_calls_log`` (no separate state to thread).
            "command_signature": _normalise_command(tc_name, tc_args),
            "result_signature": _result_signature(result_str),
        }
        result.tool_calls_log.append(log_entry)
        if state:
            state.tool_calls.append(log_entry)

        logger.info("Tool result: %d chars in %.1fs", len(result_str), tc_duration)
        if self._display:
            self._display.tool_result(
                len(result_str), tc_duration,
                preview=result_str[:150] if len(result_str) < 1000 else None,
            )
        if self._events:
            cmd = tc_args.get("command") if tc_name == "bash_exec" else None
            self._events.tool_call(
                iteration=iteration,
                tool_name=tc_name,
                command=cmd,
                result_length=len(result_str),
                duration=tc_duration,
                result_preview=result_str[:300],
            )

        detected = self.flag_detector.scan(result_str)
        if detected:
            result.flags_found.extend(detected)
            logger.info("Flag detected in tool output: %s", detected)
            if self._display:
                self._display.flag_found(detected[0], iteration)
            if self._events:
                self._events.flag_detected(iteration, detected[0], "tool_output")
            # Phase 7 P0.5 — strong nudge: many failed challenges had the
            # flag in tool output but the agent's own parsing missed it
            # (e.g. stripped the ``flag`` prefix, repr'd the bytes, etc).
            # Inject an explicit instruction so the next LLM call submits
            # via ``end_task`` immediately instead of continuing to probe.
            primary = detected[0]
            nudge = (
                "🚩 FLAG AUTO-DETECTED in the previous tool output: "
                f"`{primary}`\n\n"
                "If this matches the challenge's expected flag format, "
                "STOP exploring and call `end_task` with this exact flag "
                "string as the `flag` argument on your next turn. Do NOT "
                "modify, re-format, or re-parse it — submit it verbatim."
            )
            try:
                solver.inject_message("user", nudge)
            except Exception:  # noqa: BLE001 — defensive: never let a nudge
                # injection failure abort the run.
                logger.exception("Failed to inject flag-detected nudge")

        solver.handle_result({
            "tool_call_id": tc_id,
            "tool_name": tc_name,
            "tool_args": tc_args,
            "output": result_str,
        })

    def _maybe_inject_stagnation_nudge(
        self,
        iteration: int,
        solver: BaseSolver,
        result: OrchestratorResult,
    ) -> None:
        """ detect command/result repetition over the last few tool
        calls and inject one tactic-change nudge per detection (capped at
        ``_MAX_STAGNATION_NUDGES`` per run).

        Fires when ≥ ``_STAGNATION_THRESHOLD`` of the most recent
        ``_STAGNATION_WINDOW`` tool calls share a normalised command
        signature OR a result signature. The two checks are independent —
        either one alone is enough to trigger the nudge — because the
        repetition shapes failure differently:

          - Command repetition: agent is re-running the exact same probe.
          - Result repetition: agent is varying the probe but the target
            keeps returning the same response (e.g. constant 404).
        """
        if result.stagnation_nudges_used >= self._MAX_STAGNATION_NUDGES:
            return
        if len(result.tool_calls_log) < self._STAGNATION_THRESHOLD:
            return

        recent = result.tool_calls_log[-self._STAGNATION_WINDOW :]
        cmd_sigs = [c.get("command_signature", "") for c in recent]
        res_sigs = [c.get("result_signature", "") for c in recent]

        reason: str | None = None
        # Most-common command signature in the window.
        from collections import Counter
        cmd_top, cmd_count = Counter(cmd_sigs).most_common(1)[0]
        if cmd_count >= self._STAGNATION_THRESHOLD and cmd_top:
            preview = cmd_top.split(":", 1)[-1][:80]
            reason = (
                f"the same command was run {cmd_count} times in the last "
                f"{len(recent)} turns: `{preview}`"
            )
        else:
            res_top, res_count = Counter(res_sigs).most_common(1)[0]
            if res_count >= self._STAGNATION_THRESHOLD and res_top:
                head = res_top.split(":", 1)[-1][:80]
                reason = (
                    f"the last {res_count} of {len(recent)} tool calls all "
                    f"returned the same response (\"{head}…\")"
                )

        if reason is None:
            return

        nudge = _STAGNATION_TEMPLATE.format(reason=reason)
        try:
            solver.inject_message("user", nudge)
        except Exception:  # noqa: BLE001 — never let a nudge abort the run
            logger.exception("Failed to inject stagnation nudge")
            return

        result.stagnation_nudges_used += 1
        logger.info(
            "Stagnation nudge #%d injected at iteration %d: %s",
            result.stagnation_nudges_used, iteration, reason,
        )
        if self._events:
            self._events.stagnation_nudge(
                iteration=iteration,
                reason=reason,
                nudge_number=result.stagnation_nudges_used,
            )
