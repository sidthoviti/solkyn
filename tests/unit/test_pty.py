"""Unit tests for PTYSession + PTYExecutor.

Uses a fake `pexpect.spawn` so tests run without Docker. The fake mimics a
shell: it accumulates writes in a buffer, on `expect_exact(sentinel)` it
synthesises whatever output we've queued for that command, and exposes
`isalive()`/`close()` to satisfy the contract.

Real-Docker integration tests live behind a marker so CI without Docker
still passes.
"""

from __future__ import annotations

import os
import shutil

import pytest

from solkyn.tools.pty_executor import PTYExecutor
from solkyn.tools.pty_session import (
    PTYSession,
    PTYSessionError,
    _strip_ansi,
    _truncate,
)

# ---------------------------------------------------------------------------
# Fake pexpect spawn — programmable shell stand-in
# ---------------------------------------------------------------------------


class FakePexpectChild:
    """A toy implementation of just enough pexpect.spawn surface for tests."""

    def __init__(self, *args, **kwargs) -> None:
        self.alive = True
        # Per-command queued outputs: list[str]. Each command consumes one entry.
        self.command_outputs: list[str] = []
        # Whether the next expect should TIMEOUT.
        self.next_timeouts: list[bool] = []
        self.sent: list[str] = []
        self.before: str = ""
        self.after: str = ""
        self.closed_force: bool = False
        self.ctrl_c_count: int = 0
        # Per-call output for read_nonblocking during _drain_initial.
        self._drained = False

    # ------------------------------------------------------------------
    # pexpect surface
    # ------------------------------------------------------------------

    def send(self, data: str) -> None:
        self.sent.append(data)

    def sendline(self, data: str) -> None:
        self.sent.append(data + "\n")

    def sendcontrol(self, ch: str) -> None:
        if ch == "c":
            self.ctrl_c_count += 1

    def expect_exact(self, marker: str, timeout: float | None = None) -> int:
        if self.next_timeouts and self.next_timeouts.pop(0):
            import pexpect
            raise pexpect.TIMEOUT(f"timed out waiting for {marker}")
        if not self.command_outputs:
            self.before = ""
        else:
            self.before = self.command_outputs.pop(0)
        self.after = marker
        return 0

    def expect(self, pattern, timeout: float | None = None) -> int:
        # For _drain_initial — just say nothing more to drain.
        if not self._drained:
            self._drained = True
            return 0
        # Used by read_until — pop a single queued output.
        if self.next_timeouts and self.next_timeouts.pop(0):
            import pexpect
            raise pexpect.TIMEOUT("timed out")
        if self.command_outputs:
            self.before = self.command_outputs.pop(0)
        else:
            self.before = ""
        self.after = "<match>"
        return 0

    def read_nonblocking(self, size: int = 1, timeout: float = 0) -> str:
        # Always raise after _drain_initial's first expect call to end the loop.
        import pexpect
        raise pexpect.TIMEOUT("nothing more")

    def isalive(self) -> bool:
        return self.alive

    def close(self, force: bool = False) -> None:
        self.alive = False
        self.closed_force = force


def _mk_session(outputs: list[str] | None = None,
                timeouts: list[bool] | None = None) -> tuple[PTYSession, FakePexpectChild]:
    holder: dict[str, FakePexpectChild] = {}

    def fake_spawn(*args, **kwargs) -> FakePexpectChild:
        c = FakePexpectChild(*args, **kwargs)
        if outputs:
            c.command_outputs = list(outputs)
        if timeouts:
            c.next_timeouts = list(timeouts)
        holder["child"] = c
        return c

    s = PTYSession(
        "test-container",
        session_id="t1",
        command_timeout=2.0,
        _spawn_fn=fake_spawn,
    )
    return s, holder["child"]


# ---------------------------------------------------------------------------
# Helper unit tests
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_strip_ansi(self) -> None:
        assert _strip_ansi("\x1b[31mred\x1b[0m") == "red"

    def test_truncate_short(self) -> None:
        assert _truncate("hi", 100) == "hi"

    def test_truncate_long(self) -> None:
        out = _truncate("x" * 200, 100)
        assert out.startswith("x" * 100)
        assert "TRUNCATED" in out


# ---------------------------------------------------------------------------
# PTYSession lifecycle
# ---------------------------------------------------------------------------


class TestSessionLifecycle:
    def test_session_id_assigned(self) -> None:
        s, _ = _mk_session()
        assert s.id == "t1"
        assert s.is_alive
        assert not s.closed
        s.close()

    def test_auto_id_when_none_provided(self) -> None:
        def fake_spawn(*a, **k): return FakePexpectChild()
        s = PTYSession("c", _spawn_fn=fake_spawn)
        assert s.id.startswith("pty-")
        s.close()

    def test_close_is_idempotent(self) -> None:
        s, child = _mk_session()
        s.close()
        s.close()  # second call must not raise
        assert s.closed
        assert not child.alive

    def test_send_after_close_raises(self) -> None:
        s, _ = _mk_session()
        s.close()
        with pytest.raises(PTYSessionError):
            s.send("ls")

    def test_spawn_failure_wrapped(self) -> None:
        def fake_spawn(*a, **k):
            raise OSError("docker not found")
        with pytest.raises(PTYSessionError, match="Failed to spawn"):
            PTYSession("c", _spawn_fn=fake_spawn)


# ---------------------------------------------------------------------------
# Command send + output cleaning
# ---------------------------------------------------------------------------


class TestSend:
    def test_returns_command_output(self) -> None:
        s, _ = _mk_session(outputs=["hello world\n"])
        res = s.send("echo hello world")
        assert res["output"] == "hello world"
        assert res["timed_out"] is False
        assert res["session_id"] == "t1"

    def test_strips_ansi(self) -> None:
        s, _ = _mk_session(outputs=["\x1b[32mok\x1b[0m\n"])
        assert s.send("ls --color")["output"] == "ok"

    def test_truncates_long_output(self) -> None:
        s, _ = _mk_session(outputs=["x" * 100_000])
        out = s.send("yes")["output"]
        assert "TRUNCATED" in out

    def test_blocked_by_safety_checker(self) -> None:
        s, child = _mk_session()
        res = s.send("rm -rf /")
        assert res["output"].startswith("BLOCKED:")
        # Nothing was sent to the child.
        assert all("rm -rf /" not in m for m in child.sent[1:])

    def test_timeout_returns_timed_out_true(self) -> None:
        s, child = _mk_session(outputs=["partial\n"], timeouts=[True])
        res = s.send("sleep 999", timeout=0.1)
        assert res["timed_out"] is True
        assert "TIMED OUT" in res["output"]
        # Ctrl-C was sent to interrupt without killing the session.
        assert child.ctrl_c_count == 1
        assert s.is_alive is True

    def test_increments_command_seq_for_unique_sentinels(self) -> None:
        s, child = _mk_session(outputs=["a\n", "b\n"])
        s.send("echo a")
        s.send("echo b")
        # Both wrapped commands include unique sentinels (sequence numbers).
        wrapped = [m for m in child.sent if "SOLKYN_PROMPT" in m]
        assert len(wrapped) == 2
        assert "__1__" in wrapped[0]
        assert "__2__" in wrapped[1]


# ---------------------------------------------------------------------------
# read_until
# ---------------------------------------------------------------------------


class TestReadUntil:
    def test_returns_buffer_and_match(self) -> None:
        s, _ = _mk_session(outputs=["banner\nmsf6 > "])
        out = s.read_until(r"msf6 > ")
        assert "banner" in out

    def test_timeout_raises(self) -> None:
        s, _ = _mk_session(timeouts=[True])
        with pytest.raises(PTYSessionError, match="timed out"):
            s.read_until(r"never_matches", timeout=0.05)


# ---------------------------------------------------------------------------
# PTYExecutor pool
# ---------------------------------------------------------------------------


def _mk_executor(max_sessions: int = 4) -> PTYExecutor:
    def fake_spawn(*a, **k): return FakePexpectChild()
    return PTYExecutor(
        "test-container",
        max_sessions=max_sessions,
        _spawn_fn=fake_spawn,
    )


class TestExecutorPool:
    def test_open_returns_unique_ids(self) -> None:
        ex = _mk_executor()
        a = ex.open_session()
        b = ex.open_session()
        assert a != b
        assert set(ex.list_sessions()) == {a, b}

    def test_open_with_explicit_id(self) -> None:
        ex = _mk_executor()
        ex.open_session("alice")
        assert "alice" in ex.list_sessions()

    def test_duplicate_id_raises(self) -> None:
        ex = _mk_executor()
        ex.open_session("alice")
        with pytest.raises(PTYSessionError, match="already exists"):
            ex.open_session("alice")

    def test_pool_full_raises(self) -> None:
        ex = _mk_executor(max_sessions=2)
        ex.open_session()
        ex.open_session()
        with pytest.raises(PTYSessionError, match="pool full"):
            ex.open_session()

    def test_close_returns_true_for_existing(self) -> None:
        ex = _mk_executor()
        sid = ex.open_session()
        assert ex.close_session(sid) is True
        assert sid not in ex.list_sessions()

    def test_close_returns_false_for_missing(self) -> None:
        ex = _mk_executor()
        assert ex.close_session("nope") is False

    def test_close_all_reaps_everything(self) -> None:
        ex = _mk_executor()
        for _ in range(3):
            ex.open_session()
        ex.close_all()
        assert ex.list_sessions() == []

    def test_get_unknown_raises(self) -> None:
        ex = _mk_executor()
        with pytest.raises(PTYSessionError, match="Unknown"):
            ex.get("no-such")

    def test_run_in_session_routes(self) -> None:
        # Use a single fake child that returns "answer" for the first cmd.
        child = FakePexpectChild()
        child.command_outputs = ["answer\n"]

        def fake_spawn(*a, **k): return child
        ex = PTYExecutor("c", _spawn_fn=fake_spawn)
        sid = ex.open_session()
        out = ex.run_in_session(sid, "echo answer")
        assert out["output"] == "answer"

    def test_execute_shim_matches_docker_executor_shape(self) -> None:
        child = FakePexpectChild()
        child.command_outputs = ["hello\n"]

        def fake_spawn(*a, **k): return child
        ex = PTYExecutor("c", _spawn_fn=fake_spawn)
        out = ex.execute("echo hello")
        assert set(out.keys()) == {"stdout", "stderr", "exit_code", "timed_out"}
        assert out["stdout"] == "hello"
        assert out["timed_out"] is False
        # Session was opened then closed.
        assert ex.list_sessions() == []


# ===========================================================================
# Docker-required integration tests (skipped when Docker absent)
# ===========================================================================


_DOCKER = shutil.which("docker") is not None and os.environ.get("SOLKYN_PTY_INTEGRATION") == "1"


@pytest.mark.skipif(not _DOCKER, reason="Set SOLKYN_PTY_INTEGRATION=1 with Docker to run")
class TestPTYRealDocker:
    """Live PTY tests against a transient Kali container.

    These cover  (session persistence: cd then pwd, export then echo,
    independent sessions) and  (safety still blocks rm -rf /).
    """

    @pytest.fixture
    def container(self):
        import subprocess
        import uuid
        name = f"solkyn-pty-test-{uuid.uuid4().hex[:8]}"
        subprocess.run(
            ["docker", "run", "-d", "--rm", "--name", name,
             "kalilinux/kali-rolling", "sleep", "300"],
            check=True, capture_output=True,
        )
        yield name
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)

    def test_cd_persists(self, container):
        s = PTYSession(container)
        try:
            s.send("cd /tmp")
            res = s.send("pwd")
            assert "/tmp" in res["output"]
        finally:
            s.close()

    def test_export_persists(self, container):
        s = PTYSession(container)
        try:
            s.send("export X=foo123")
            res = s.send("echo $X")
            assert "foo123" in res["output"]
        finally:
            s.close()

    def test_two_sessions_independent(self, container):
        ex = PTYExecutor(container)
        a = ex.open_session()
        b = ex.open_session()
        try:
            ex.run_in_session(a, "export VAR=alice")
            ex.run_in_session(b, "export VAR=bob")
            assert "alice" in ex.run_in_session(a, "echo $VAR")["output"]
            assert "bob" in ex.run_in_session(b, "echo $VAR")["output"]
        finally:
            ex.close_all()

    def test_rm_rf_blocked(self, container):
        s = PTYSession(container)
        try:
            res = s.send("rm -rf /")
            assert res["output"].startswith("BLOCKED:")
        finally:
            s.close()
