"""Exit-reason vocabulary for solver runs.

Single source of truth for the strings that are allowed to appear in
``stats.json["exit_reason"]``. Centralised here so callers in the
orchestrator, run script, reporting layer, and tests all agree.

The vocabulary is intentionally narrow \u2014 every reason maps to a
distinct outer-loop branch in :class:`solkyn.agents.orchestrator.Orchestrator`
or to an unhandled exception fallthrough. Future labels (``refusal``,
``crash``, ``stuck_loop``, ...) require their own detection logic and
should land in a dedicated change rather than be silently added to the
allow-list.
"""

from __future__ import annotations

from typing import Final, Literal

# Typed alias for static checkers \u2014 mirrored in
# :class:`solkyn.agents.orchestrator.OrchestratorResult`.
ExitReason = Literal[
    "flag_found",
    "max_iterations",
    "no_tool_calls",
    "time_limit",
    "cost_limit",
    "error",
]

EXIT_REASONS: Final[frozenset[str]] = frozenset({
    "flag_found",
    "max_iterations",
    "no_tool_calls",
    "time_limit",
    "cost_limit",
    "error",
})


class InvalidExitReasonError(ValueError):
    """Raised when a value outside :data:`EXIT_REASONS` is written."""


def validate_exit_reason(reason: str | None, *, strict: bool = True) -> str:
    """Validate ``reason`` against :data:`EXIT_REASONS`.

    Args:
        reason: Candidate string. ``None`` is treated as the legacy
            no-exit-reason case and coerced to ``"error"`` (so the
            resulting JSON is never schema-invalid).
        strict: If True (default) raise :class:`InvalidExitReasonError`
            on an unknown value; if False, log + coerce to ``"error"``
            so a production run can still write its artefacts.

    Returns:
        A validated exit-reason string drawn from :data:`EXIT_REASONS`.
    """
    if reason is None:
        return "error"
    if reason in EXIT_REASONS:
        return reason
    if strict:
        raise InvalidExitReasonError(
            f"Unknown exit_reason {reason!r}. "
            f"Allowed: {sorted(EXIT_REASONS)}"
        )
    return "error"
