"""PTYExecutor — manages a pool of :class:`PTYSession` objects keyed
by session id. Exposed alongside :class:`DockerExecutor` so the agent can use
either or both via the registered tools (``pty_open``/``pty_run``/``pty_close``).

Design notes:

* Sessions are created lazily by ``open_session()`` (or implicitly by ``run()``
  when given a fresh id).
* All sessions share the same container — this is per-attempt, single-target.
* ``close_all()`` is called at orchestrator teardown so we never leak processes
  across challenges. The CLI runner wires this in .
"""

from __future__ import annotations

import logging
from typing import Any

from solkyn.tools.pty_session import (
    DEFAULT_COMMAND_TIMEOUT,
    DEFAULT_OUTPUT_LIMIT,
    PTYSession,
    PTYSessionError,
)

logger = logging.getLogger(__name__)


class PTYExecutor:
    """Pool of long-lived shell sessions in a Kali container.

    Implements the same shape (``execute(command)`` returning ``{stdout,
    stderr, exit_code, timed_out}``) so the existing ``bash_exec`` tool
    contract can wrap it transparently when desired — but the *primary*
    surface is the ``open_session``/``run_in_session``/``close_session``
    methods exposed via the new pty tools.
    """

    def __init__(
        self,
        container_name: str,
        *,
        default_timeout: float = DEFAULT_COMMAND_TIMEOUT,
        output_limit: int = DEFAULT_OUTPUT_LIMIT,
        max_sessions: int = 16,
        # Test injection point — overrides PTYSession's spawn function.
        _spawn_fn: Any = None,
    ) -> None:
        self.container_name = container_name
        self.default_timeout = default_timeout
        self.output_limit = output_limit
        self.max_sessions = max_sessions
        self._sessions: dict[str, PTYSession] = {}
        self._spawn_fn = _spawn_fn

    # ------------------------------------------------------------------
    # Pool management
    # ------------------------------------------------------------------

    def open_session(self, session_id: str | None = None) -> str:
        """Spawn a new PTY session, return its id."""
        if len(self._sessions) >= self.max_sessions:
            raise PTYSessionError(
                f"Session pool full ({self.max_sessions} sessions). "
                "Close one first via pty_close."
            )
        if session_id and session_id in self._sessions:
            raise PTYSessionError(f"Session {session_id} already exists")
        session = PTYSession(
            self.container_name,
            session_id=session_id,
            command_timeout=self.default_timeout,
            output_limit=self.output_limit,
            _spawn_fn=self._spawn_fn,
        )
        self._sessions[session.id] = session
        logger.info("Opened PTY session %s in %s", session.id, self.container_name)
        return session.id

    def close_session(self, session_id: str) -> bool:
        """Close one session. Returns True if it existed."""
        sess = self._sessions.pop(session_id, None)
        if sess is None:
            return False
        sess.close()
        return True

    def close_all(self) -> None:
        """Reap every open session. Safe to call multiple times."""
        for sess in list(self._sessions.values()):
            try:
                sess.close()
            except Exception as e:
                logger.warning("Error closing %s: %s", sess.id, e)
        self._sessions.clear()

    def list_sessions(self) -> list[str]:
        return list(self._sessions.keys())

    def get(self, session_id: str) -> PTYSession:
        sess = self._sessions.get(session_id)
        if sess is None:
            raise PTYSessionError(f"Unknown session {session_id}")
        return sess

    # ------------------------------------------------------------------
    # Command execution
    # ------------------------------------------------------------------

    def run_in_session(
        self,
        session_id: str,
        command: str,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """Run ``command`` in the named session, returning the
        :meth:`PTYSession.send` dict."""
        return self.get(session_id).send(command, timeout=timeout)

    def read_until(
        self,
        session_id: str,
        prompt_regex: str,
        timeout: float | None = None,
    ) -> str:
        return self.get(session_id).read_until(prompt_regex, timeout=timeout)

    # ------------------------------------------------------------------
    # DockerExecutor-compatible shim
    # ------------------------------------------------------------------

    def execute(self, command: str) -> dict[str, Any]:
        """One-shot fallback: spawn a session, run, close. Matches the
        ``DockerExecutor.execute`` shape so callers with the legacy contract
        work. NOTE: this discards persistence — prefer ``run_in_session``."""
        sid = self.open_session()
        try:
            res = self.run_in_session(sid, command)
            return {
                "stdout": res["output"],
                "stderr": "",
                "exit_code": -1 if res["timed_out"] else 0,
                "timed_out": res["timed_out"],
            }
        finally:
            self.close_session(sid)
