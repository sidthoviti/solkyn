"""Pluggable solver strategies for the Solkyn agent loop.

A *solver* is a strategy for "given current state, what should we do next?".
The orchestrator owns the outer loop, limits, executor, flag validation and
state save; it calls the solver via :class:`BaseSolver.get_next_action` and
feeds the executor's result back via :meth:`BaseSolver.handle_result`.

This split lets us add new solving strategies (HackSynth dual-LLM,
context-compaction, external CLI agents) as sibling implementations rather
than forks of the loop body.

See ``the solver architecture notes
``docs/research-boxpwnr-analysis.md`` for design context.
"""

from __future__ import annotations

from typing import Any

from solkyn.agents.solvers.base import BaseSolver, SolverAction
from solkyn.agents.solvers.single_loop import SingleLoopSolver

__all__ = [
    "BaseSolver",
    "SingleLoopSolver",
    "SolverAction",
    "SOLVER_NAMES",
    "get_solver",
]


# Canonical list of registered solver names. Kept in sync with
# scripts/run_challenges.py --solver choices and solver.py validation.
SOLVER_NAMES: tuple[str, ...] = ("single_loop", "single_loop_compact", "hacksynth")


def get_solver(name: str, /, **kwargs: Any) -> BaseSolver:
    """Construct a solver by name.

    Parameters
    ----------
    name
        One of :data:`SOLVER_NAMES`.
    **kwargs
        Solver-specific constructor arguments. Common keys: ``llm_manager``,
        ``tool_schemas``, ``flag_detector``, ``tags``, ``max_nudges``.
        ``hacksynth`` recognises ``planner_llm`` and ``summarizer_llm``;
        if not provided it falls back to ``llm_manager`` for the planner
        (and reuses it for the summarizer).

    Returns
    -------
    BaseSolver
        A constructed solver instance.

    Raises
    ------
    ValueError
        If ``name`` is not a registered solver.
    """
    if name == "single_loop":
        return SingleLoopSolver(
            llm_manager=kwargs["llm_manager"],
            tool_schemas=kwargs.get("tool_schemas"),
            flag_detector=kwargs.get("flag_detector"),
            tags=kwargs.get("tags"),
            max_nudges=kwargs.get("max_nudges", 3),
        )
    if name == "single_loop_compact":
        from solkyn.agents.solvers.single_loop_compact import SingleLoopCompactSolver

        return SingleLoopCompactSolver(
            llm_manager=kwargs["llm_manager"],
            tool_schemas=kwargs.get("tool_schemas"),
            flag_detector=kwargs.get("flag_detector"),
            tags=kwargs.get("tags"),
            max_nudges=kwargs.get("max_nudges", 3),
        )
    if name == "hacksynth":
        from solkyn.agents.solvers.hacksynth import HackSynthSolver

        planner_llm = kwargs.get("planner_llm") or kwargs.get("llm_manager")
        if planner_llm is None:
            raise ValueError(
                "hacksynth solver requires either 'planner_llm' or 'llm_manager'"
            )
        return HackSynthSolver(
            planner_llm=planner_llm,
            summarizer_llm=kwargs.get("summarizer_llm"),
            flag_detector=kwargs.get("flag_detector"),
            tags=kwargs.get("tags"),
        )
    raise ValueError(
        f"Unknown solver: {name!r}. Available: {', '.join(SOLVER_NAMES)}"
    )
