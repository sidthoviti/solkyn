""" tests for the solver factory + ``--solver`` CLI plumbing.

Verifies:
* :func:`solkyn.agents.solvers.get_solver` returns the right concrete
  class for each registered name.
* Unknown names raise ``ValueError``.
* :data:`SOLVER_NAMES` matches the CLI ``--solver`` choices in
  ``scripts/run_challenges.py``.
* :data:`SOLVER_NAMES` matches :class:`SolverAgent` validation.
* Default ``configs/default.yaml`` carries the new ``solver:`` block.
* ``--solver hacksynth`` is advertised in ``--help``.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

from solkyn.agents.solvers import (
    SOLVER_NAMES,
    BaseSolver,
    SingleLoopSolver,
    get_solver,
)
from solkyn.agents.solvers.hacksynth import HackSynthSolver
from solkyn.agents.solvers.single_loop_compact import SingleLoopCompactSolver


@pytest.fixture
def llm():
    return MagicMock()


class TestSolverFactory:
    def test_returns_single_loop(self, llm):
        s = get_solver("single_loop", llm_manager=llm, tool_schemas=None)
        assert isinstance(s, SingleLoopSolver)
        assert isinstance(s, BaseSolver)
        # Should NOT be a SingleLoopCompactSolver subclass instance.
        assert type(s) is SingleLoopSolver

    def test_returns_single_loop_compact(self, llm):
        s = get_solver("single_loop_compact", llm_manager=llm, tool_schemas=None)
        assert isinstance(s, SingleLoopCompactSolver)
        assert isinstance(s, SingleLoopSolver)  # subclass

    def test_returns_hacksynth(self, llm):
        s = get_solver("hacksynth", llm_manager=llm)
        assert isinstance(s, HackSynthSolver)

    def test_hacksynth_reuses_llm_when_planner_not_specified(self, llm):
        s = get_solver("hacksynth", llm_manager=llm)
        # Both planner + summarizer share the same LLM handle.
        assert s._planner is llm
        assert s._summarizer is llm

    def test_hacksynth_explicit_planner_summarizer(self):
        planner = MagicMock(name="planner")
        summarizer = MagicMock(name="summarizer")
        s = get_solver("hacksynth", planner_llm=planner, summarizer_llm=summarizer)
        assert s._planner is planner
        assert s._summarizer is summarizer

    def test_hacksynth_requires_a_planner_or_llm_manager(self):
        with pytest.raises(ValueError, match="planner_llm.*llm_manager"):
            get_solver("hacksynth")

    def test_unknown_solver_raises_with_available_names(self, llm):
        with pytest.raises(ValueError, match="Unknown solver"):
            get_solver("not_a_real_solver", llm_manager=llm)
        # Error message must enumerate the valid options.
        with pytest.raises(ValueError) as ei:
            get_solver("ghost", llm_manager=llm)
        msg = str(ei.value)
        for name in SOLVER_NAMES:
            assert name in msg

    def test_solver_names_is_complete(self):
        # If we add a new solver, this guards against forgetting to
        # register it. Each name must produce a working factory call.
        assert "single_loop" in SOLVER_NAMES
        assert "single_loop_compact" in SOLVER_NAMES
        assert "hacksynth" in SOLVER_NAMES

    def test_factory_passes_tags_through(self, llm):
        tags = ["SQLi", "IDOR"]
        s = get_solver("single_loop", llm_manager=llm, tool_schemas=None, tags=tags)
        assert s.tags == tags


class TestSolverAgentValidatesSolverName:
    def test_accepts_all_registered_names(self, llm):
        from solkyn.agents.solver import SolverAgent
        from solkyn.tools.registry import ToolRegistry
        for name in SOLVER_NAMES:
            agent = SolverAgent(
                llm_manager=llm,
                tool_registry=ToolRegistry(),
                solver_name=name,
            )
            assert agent._solver_name == name

    def test_rejects_unknown_name(self, llm):
        from solkyn.agents.solver import SolverAgent
        from solkyn.tools.registry import ToolRegistry
        with pytest.raises(ValueError, match="Unknown solver_name"):
            SolverAgent(
                llm_manager=llm,
                tool_registry=ToolRegistry(),
                solver_name="bogus_solver",
            )


class TestDefaultConfigCarriesSolverBlock:
    def test_solver_section_present(self):
        repo_root = Path(__file__).resolve().parents[2]
        cfg_path = repo_root / "configs" / "default.yaml"
        cfg = yaml.safe_load(cfg_path.read_text())
        assert "solver" in cfg, "configs/default.yaml missing 'solver' section"
        assert cfg["solver"].get("name") in SOLVER_NAMES
        # Hacksynth subsection with the two model slots.
        hs = cfg["solver"].get("hacksynth", {})
        assert "planner_model" in hs
        assert "summarizer_model" in hs


class TestRunChallengesCliAdvertisesHacksynth:
    def test_help_lists_hacksynth(self):
        repo_root = Path(__file__).resolve().parents[2]
        script = repo_root / "scripts" / "run_challenges.py"
        result = subprocess.run(
            [sys.executable, str(script), "--help"],
            capture_output=True, text=True, timeout=30, cwd=repo_root,
        )
        assert result.returncode == 0, result.stderr
        # All three solver choices must be advertised.
        for name in SOLVER_NAMES:
            assert name in result.stdout, f"{name} missing from --help"
