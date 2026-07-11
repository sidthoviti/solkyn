"""BaseSolver interface + SolverAction message type.

A solver is the *strategy* layer — given the current state of an attempt,
return the next thing the orchestrator should do. Solvers know nothing
about iteration caps, deadlines, the executor, or the platform; the
orchestrator handles all of that and feeds the solver back the result of
each command.

Why an interface? So we can ship multiple strategies side-by-side
(``SingleLoopSolver`` mirroring the current behaviour, ``HackSynthSolver``
with planner/summarizer split, ``SingleLoopCompactSolver`` with rolling
context compaction) without forking the loop body. The orchestrator stays
strategy-agnostic.

See ``the solver architecture notes
``docs/research-boxpwnr-analysis.md`` for the BoxPwnr design this mirrors.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


class SolverAction(BaseModel):
    """One step the orchestrator should take, as decided by the solver.

    Three action types:

    * ``command`` — execute ``command`` via the executor; the orchestrator
      will call :meth:`BaseSolver.handle_result` with the execution result.
    * ``flag`` — the solver believes ``flag`` is the answer; the orchestrator
      validates against the platform.
    * ``none`` — the solver has nothing to propose this iteration. The
      orchestrator decides whether to inject a "try harder" message
 or terminate.

    ``reasoning`` is a free-form short explanation surfaced into traces.
    ``tool_name`` and ``tool_args`` are the structured form of ``command``;
    populated when the solver used native LLM tool-calling (so the
    orchestrator can dispatch through the tool registry rather than
    re-parsing the command string).
    """

    type: Literal["command", "flag", "none"]
    command: str | None = None
    flag: str | None = None
    reasoning: str | None = None
    tool_name: str | None = None
    tool_args: dict[str, Any] | None = None
    tool_call_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate_payload(self) -> SolverAction:
        if self.type == "command" and self.command is None and self.tool_name is None:
            msg = "SolverAction(type='command') requires either 'command' or 'tool_name'"
            raise ValueError(msg)
        if self.type == "flag" and not self.flag:
            msg = "SolverAction(type='flag') requires non-empty 'flag'"
            raise ValueError(msg)
        return self


class BaseSolver(ABC):
    """Strategy interface for deciding the next action in a solve attempt.

    Lifecycle::

        solver = SomeSolver(...)
        solver.initialize(system_prompt)
        while not done:
            action = solver.get_next_action()
            if action.type == "command":
                result = executor.execute(...)
                solver.handle_result(result)
            elif action.type == "flag":
                ...validate...
            elif action.type == "none":
                ...orchestrator nudges or terminates...
        trace = solver.serialize_conversation()
    """

    @abstractmethod
    def initialize(self, system_prompt: str) -> None:
        """Prepare internal state with the rendered system prompt."""

    @abstractmethod
    def get_next_action(self) -> SolverAction:
        """Decide the next action. Pure (no side effects on executor/platform)."""

    @abstractmethod
    def handle_result(self, result: dict[str, Any]) -> None:
        """Feed back the executor's result for the most recent command action.

        ``result`` is the raw executor return value (e.g. dict with
        ``stdout``, ``stderr``, ``exit_code``, ``timed_out``) plus any
        orchestrator-added fields (``tool_call_id``, ``tool_name``).
        """

    def should_ignore_max_iterations(self) -> bool:
        """If True, the orchestrator's ``--max-iterations`` cap is bypassed.

        Used by autonomous solvers (e.g. ``claude_code`` in BoxPwnr) where
        turn-counting is meaningless. Default False.
        """
        return False

    def get_solver_prompt_file(self) -> str | None:
        """Optional solver-specific prompt fragment path.

        Returned path is appended to the generic system prompt by the
        prompt builder. Default ``None`` means no solver-specific prompt.
        """
        return None

    @abstractmethod
    def serialize_conversation(self) -> dict[str, Any]:
        """Return the full conversation trace for persistence + reporting.

        Two formats are recognised by the report generator:

        * ``{"format": "flat", "messages": [...]}`` — single-agent solvers.
        * ``{"format": "nested", "turns": [...]}`` — multi-agent solvers
          (HackSynth-style planner + summarizer per turn).
        """

    def inject_message(self, role: str, content: str) -> None:
        """Inject a message into the conversation (orchestrator → solver).

        Used by the orchestrator's stuck-handling layer to feed
        "try harder" / tool-error nudges back into the model. Default
        implementation is a no-op so solvers that don't need it can ignore
        the contract; subclasses that maintain a message list should
        override.
        """
        return None

    def get_iteration_count(self) -> int:
        """Logical iteration count used by the orchestrator's max-iterations cap.

        For ``SingleLoopSolver`` this is the number of LLM calls made (so a
        single LLM response with 3 parallel tool calls counts as one
        iteration, matching pre-refactor behaviour). Subclasses should
        increment whatever unit best maps to "one chunk of solver work".
        Default returns 0 (subclasses must override to participate in the
        iteration cap).
        """
        return 0
