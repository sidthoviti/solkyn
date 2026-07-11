""" tests for ``register_pty_tools`` and the ``--executor pty`` CLI flag.

These tests use a :class:`MagicMock` in place of a real ``PTYExecutor`` so they
run without Docker. The end-to-end behaviour with a live container is covered
by the gated tests in ``test_pty.py`` (``SOLKYN_PTY_INTEGRATION=1``).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from solkyn.tools.registry import ToolRegistry, create_default_tools, register_pty_tools


@pytest.fixture
def mock_pty_executor() -> MagicMock:
    """A MagicMock standing in for ``PTYExecutor``."""
    m = MagicMock()
    m.max_sessions = 16
    return m


@pytest.fixture
def empty_registry() -> ToolRegistry:
    return ToolRegistry()


# ---------------------------------------------------------------------------
# register_pty_tools — registry shape
# ---------------------------------------------------------------------------


class TestRegisterPtyTools:
    def test_returns_same_registry_instance(self, empty_registry, mock_pty_executor):
        out = register_pty_tools(empty_registry, mock_pty_executor)
        assert out is empty_registry

    def test_adds_exactly_three_tools_to_empty_registry(
        self, empty_registry, mock_pty_executor
    ):
        register_pty_tools(empty_registry, mock_pty_executor)
        names = {s["function"]["name"] for s in empty_registry.get_schemas()}
        assert names == {"pty_open", "pty_run", "pty_close"}

    def test_coexists_with_default_tools(self, mock_pty_executor):
        # Mock executor for create_default_tools.
        docker_exec = MagicMock()
        registry = create_default_tools(docker_exec)
        before = {s["function"]["name"] for s in registry.get_schemas()}
        register_pty_tools(registry, mock_pty_executor)
        after = {s["function"]["name"] for s in registry.get_schemas()}
        # The 3 originals stay, the 3 PTY tools are added.
        assert after == before | {"pty_open", "pty_run", "pty_close"}
        assert len(after) == len(before) + 3

    def test_pty_run_schema_has_required_args(self, empty_registry, mock_pty_executor):
        register_pty_tools(empty_registry, mock_pty_executor)
        schemas = {s["function"]["name"]: s for s in empty_registry.get_schemas()}
        pr = schemas["pty_run"]["function"]["parameters"]
        assert set(pr["required"]) == {"session_id", "command"}
        assert "timeout" in pr["properties"]

    def test_pty_close_schema_requires_session_id(
        self, empty_registry, mock_pty_executor
    ):
        register_pty_tools(empty_registry, mock_pty_executor)
        schemas = {s["function"]["name"]: s for s in empty_registry.get_schemas()}
        assert schemas["pty_close"]["function"]["parameters"]["required"] == [
            "session_id"
        ]

    def test_pty_open_schema_no_required_args(self, empty_registry, mock_pty_executor):
        register_pty_tools(empty_registry, mock_pty_executor)
        schemas = {s["function"]["name"]: s for s in empty_registry.get_schemas()}
        assert schemas["pty_open"]["function"]["parameters"]["required"] == []


# ---------------------------------------------------------------------------
# pty_open handler
# ---------------------------------------------------------------------------


class TestPtyOpenHandler:
    def test_opens_session_with_explicit_id(self, empty_registry, mock_pty_executor):
        mock_pty_executor.open_session.return_value = "listener"
        register_pty_tools(empty_registry, mock_pty_executor)
        out = empty_registry.execute_tool("pty_open", {"session_id": "listener"})
        mock_pty_executor.open_session.assert_called_once_with("listener")
        assert "listener" in out
        assert out.startswith("OK:")

    def test_opens_session_with_auto_id(self, empty_registry, mock_pty_executor):
        mock_pty_executor.open_session.return_value = "pty-0"
        register_pty_tools(empty_registry, mock_pty_executor)
        out = empty_registry.execute_tool("pty_open", {})
        mock_pty_executor.open_session.assert_called_once_with(None)
        assert "pty-0" in out
        assert out.startswith("OK:")

    def test_executor_failure_returns_error_string(
        self, empty_registry, mock_pty_executor
    ):
        mock_pty_executor.open_session.side_effect = RuntimeError("pool full")
        register_pty_tools(empty_registry, mock_pty_executor)
        out = empty_registry.execute_tool("pty_open", {})
        assert out.startswith("ERROR")
        assert "pool full" in out

    def test_handler_absorbs_unknown_kwargs(self, empty_registry, mock_pty_executor):
        mock_pty_executor.open_session.return_value = "x"
        register_pty_tools(empty_registry, mock_pty_executor)
        # Some models inject extra args; the handler must not crash.
        out = empty_registry.execute_tool(
            "pty_open", {"session_id": None, "extra": "ignored"}
        )
        assert out.startswith("OK:")


# ---------------------------------------------------------------------------
# pty_run handler
# ---------------------------------------------------------------------------


class TestPtyRunHandler:
    def test_returns_output_string_on_success(
        self, empty_registry, mock_pty_executor
    ):
        mock_pty_executor.run_in_session.return_value = {
            "output": "/tmp",
            "timed_out": False,
            "session_id": "s1",
        }
        register_pty_tools(empty_registry, mock_pty_executor)
        out = empty_registry.execute_tool(
            "pty_run", {"session_id": "s1", "command": "pwd"}
        )
        mock_pty_executor.run_in_session.assert_called_once_with(
            "s1", "pwd", timeout=None
        )
        assert out == "/tmp"

    def test_passes_timeout_through(self, empty_registry, mock_pty_executor):
        mock_pty_executor.run_in_session.return_value = {
            "output": "ok", "timed_out": False, "session_id": "s1",
        }
        register_pty_tools(empty_registry, mock_pty_executor)
        empty_registry.execute_tool(
            "pty_run",
            {"session_id": "s1", "command": "sleep 1; echo ok", "timeout": 5},
        )
        mock_pty_executor.run_in_session.assert_called_once_with(
            "s1", "sleep 1; echo ok", timeout=5
        )

    def test_timed_out_returns_output_unchanged(
        self, empty_registry, mock_pty_executor
    ):
        mock_pty_executor.run_in_session.return_value = {
            "output": "partial...\n[TIMED OUT after 30s — sent Ctrl-C]",
            "timed_out": True,
            "session_id": "s1",
        }
        register_pty_tools(empty_registry, mock_pty_executor)
        out = empty_registry.execute_tool(
            "pty_run", {"session_id": "s1", "command": "tail -f /dev/null"}
        )
        assert "TIMED OUT" in out
        assert out.startswith("partial")

    def test_empty_output_indicates_session_alive(
        self, empty_registry, mock_pty_executor
    ):
        mock_pty_executor.run_in_session.return_value = {
            "output": "",
            "timed_out": False,
            "session_id": "s1",
        }
        register_pty_tools(empty_registry, mock_pty_executor)
        out = empty_registry.execute_tool(
            "pty_run", {"session_id": "s1", "command": "true"}
        )
        assert "no output" in out
        assert "s1" in out

    def test_executor_failure_returns_error_string(
        self, empty_registry, mock_pty_executor
    ):
        mock_pty_executor.run_in_session.side_effect = KeyError("unknown-sid")
        register_pty_tools(empty_registry, mock_pty_executor)
        out = empty_registry.execute_tool(
            "pty_run", {"session_id": "unknown-sid", "command": "pwd"}
        )
        assert out.startswith("ERROR")
        assert "unknown-sid" in out


# ---------------------------------------------------------------------------
# pty_close handler
# ---------------------------------------------------------------------------


class TestPtyCloseHandler:
    def test_existing_session_returns_ok(self, empty_registry, mock_pty_executor):
        mock_pty_executor.close_session.return_value = True
        register_pty_tools(empty_registry, mock_pty_executor)
        out = empty_registry.execute_tool("pty_close", {"session_id": "s1"})
        mock_pty_executor.close_session.assert_called_once_with("s1")
        assert out.startswith("OK:")
        assert "s1" in out

    def test_unknown_session_returns_warn(self, empty_registry, mock_pty_executor):
        mock_pty_executor.close_session.return_value = False
        register_pty_tools(empty_registry, mock_pty_executor)
        out = empty_registry.execute_tool("pty_close", {"session_id": "ghost"})
        assert out.startswith("WARN")
        assert "ghost" in out

    def test_executor_failure_returns_error_string(
        self, empty_registry, mock_pty_executor
    ):
        mock_pty_executor.close_session.side_effect = RuntimeError("boom")
        register_pty_tools(empty_registry, mock_pty_executor)
        out = empty_registry.execute_tool("pty_close", {"session_id": "s1"})
        assert out.startswith("ERROR")
        assert "boom" in out


# ---------------------------------------------------------------------------
# CLI smoke test — `--executor` flag is wired
# ---------------------------------------------------------------------------


class TestRunChallengesCliFlag:
    """Sanity-check that ``scripts/run_challenges.py --help`` advertises the
    new ``--executor`` flag without importing the module (which would pull in
    heavy deps)."""

    def test_help_lists_executor_flag(self):
        repo_root = Path(__file__).resolve().parents[2]
        script = repo_root / "scripts" / "run_challenges.py"
        assert script.exists(), script
        result = subprocess.run(
            [sys.executable, str(script), "--help"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=repo_root,
        )
        assert result.returncode == 0, result.stderr
        assert "--executor" in result.stdout
        # Both choices must appear in the help text.
        assert "docker" in result.stdout
        assert "pty" in result.stdout
