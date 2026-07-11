"""PTYSession — a single persistent shell session inside the Kali
container, driven over a host-side pty via :mod:`pexpect`.

We launch ``docker exec -it <container> bash`` so the child shell:

* keeps a pty (so interactive tools like ``mysql``, ``msfconsole``, ``nc -lvnp``
  work and ``cd``/``export``/``source`` persist),
* runs in the same container as the stateless ``DockerExecutor``.

The session protocol is dead simple: after every command we emit a sentinel
string (``__SOLKYN_PROMPT__<id>__<seq>__``) and ``read_until`` it. This avoids
having to parse the user's PS1 prompt and is robust to colored / customized
prompts.
"""

from __future__ import annotations

import logging
import re
import time
import uuid
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pexpect

logger = logging.getLogger(__name__)


# Default per-command timeout (seconds). The session itself can outlive any
# single command — we only kill the child if `close()` is called.
DEFAULT_COMMAND_TIMEOUT = 30

# Per-command output cap (chars). Long-running tools (msfconsole, hydra)
# can flood; we apply the same kind of guard `DockerExecutor` uses.
DEFAULT_OUTPUT_LIMIT = 50_000

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return (
        text[:limit]
        + f"\n... [OUTPUT TRUNCATED — {len(text)} chars, showing first {limit} chars]"
    )


class PTYSessionError(RuntimeError):
    """Raised on session lifecycle errors (spawn failure, dead child, etc.)."""


class PTYSession:
    """A single persistent ``docker exec -it`` bash session."""

    def __init__(
        self,
        container_name: str,
        *,
        session_id: str | None = None,
        spawn_timeout: float = 10.0,
        command_timeout: float = DEFAULT_COMMAND_TIMEOUT,
        output_limit: int = DEFAULT_OUTPUT_LIMIT,
        # Injection point for tests — defaults to the real pexpect.spawn.
        _spawn_fn=None,
    ) -> None:
        self.container_name = container_name
        self.id = session_id or f"pty-{uuid.uuid4().hex[:8]}"
        self.command_timeout = command_timeout
        self.output_limit = output_limit
        self.started_at = time.time()
        self.last_activity = self.started_at
        self._closed = False
        self._command_seq = 0
        self._sentinel_base = f"__SOLKYN_PROMPT__{self.id}__"

        spawn_fn = _spawn_fn
        if spawn_fn is None:
            import pexpect
            spawn_fn = pexpect.spawn

        try:
            self._child: pexpect.spawn = spawn_fn(
                "docker",
                ["exec", "-i", container_name, "bash", "--noprofile", "--norc"],
                encoding="utf-8",
                timeout=spawn_timeout,
                echo=False,
                # Reasonable terminal size so tools like `less` don't trip.
                dimensions=(40, 200),
            )
        except Exception as e:
            raise PTYSessionError(
                f"Failed to spawn docker exec for {container_name}: {e}"
            ) from e

        # Disable bash prompt + history side-effects so output stays clean.
        # We don't need to read the response — `send()` will sync via sentinel.
        self._child.sendline("export PS1='' HISTFILE=/dev/null TERM=dumb 2>/dev/null")
        # Drain the initial output (anything printed before our first command).
        self._drain_initial()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _drain_initial(self) -> None:
        """Discard whatever the shell printed at startup so the first
        ``send()`` doesn't see banner text."""
        try:
            self._child.expect([r".+", "\r\n"], timeout=0.5)
        except Exception:
            pass  # nothing to drain
        # Now flush anything else cheaply.
        try:
            while True:
                self._child.read_nonblocking(size=1024, timeout=0.05)
        except Exception:
            pass

    def close(self) -> None:
        """Reap the child process. Idempotent."""
        if self._closed:
            return
        self._closed = True
        try:
            self._child.sendline("exit")
        except Exception:
            pass
        try:
            self._child.close(force=True)
        except Exception:
            pass
        logger.info("PTY session %s closed", self.id)

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def is_alive(self) -> bool:
        if self._closed:
            return False
        try:
            return bool(self._child.isalive())
        except Exception:
            return False

    # ------------------------------------------------------------------
    # I/O
    # ------------------------------------------------------------------

    def send(self, command: str, timeout: float | None = None) -> dict:
        """Send a command to the shell, wait for completion, return the output.

        Safety check is applied first (same SafetyChecker as DockerExecutor).
        On per-command timeout the session is *not* killed — we send Ctrl-C
        and return what we have so far.

        Returns a dict with keys: ``output``, ``timed_out``, ``session_id``.
        """
        from solkyn.tools.safety import SafetyChecker

        if self._closed:
            raise PTYSessionError(f"Session {self.id} is closed")

        is_safe, reason = SafetyChecker().check_command(command)
        if not is_safe:
            logger.warning("Blocked PTY command in %s: %s — %s", self.id, command, reason)
            return {
                "output": f"BLOCKED: {reason}",
                "timed_out": False,
                "session_id": self.id,
            }

        self._command_seq += 1
        sentinel = f"{self._sentinel_base}{self._command_seq}__"
        wait = timeout if timeout is not None else self.command_timeout

        # Send the command, then a marker echo so we know when it finishes.
        # We append `; printf '\\n%s\\n' '<sentinel>'` so even commands that
        # don't print a newline at the end give us a clean delimiter.
        wrapped = f"{command}\nprintf '\\n%s\\n' '{sentinel}'\n"
        try:
            self._child.send(wrapped)
        except Exception as e:
            raise PTYSessionError(f"send failed on {self.id}: {e}") from e

        timed_out = False
        try:
            self._child.expect_exact(sentinel, timeout=wait)
            output = self._child.before or ""
        except Exception as e:
            # Likely a TIMEOUT. Send Ctrl-C to interrupt the command but
            # keep the session alive for the next one.
            timed_out = True
            try:
                self._child.sendcontrol("c")
                # Best-effort: try to consume the rest of the output, capped.
                output = self._child.before or ""
                try:
                    self._child.expect_exact(sentinel, timeout=2.0)
                    output = self._child.before or output
                except Exception:
                    pass
            except Exception:
                output = ""
            logger.warning(
                "PTY command timed out after %ss on %s: %s",
                wait, self.id, str(e).splitlines()[0][:120],
            )

        self.last_activity = time.time()

        # Strip the wrapped command + sentinel echo from output.
        cleaned = _strip_ansi(output)
        # Drop the leading echo of our wrapper line if it appears (echo=False
        # should prevent this, but be defensive).
        for prefix in (wrapped, command):
            if cleaned.startswith(prefix):
                cleaned = cleaned[len(prefix):]
                break
        cleaned = cleaned.lstrip("\r\n")
        if cleaned.endswith(sentinel):
            cleaned = cleaned[: -len(sentinel)]
        cleaned = cleaned.rstrip("\r\n")

        if timed_out:
            cleaned += f"\n[TIMED OUT after {wait}s — session still alive, command interrupted]"

        return {
            "output": _truncate(cleaned, self.output_limit),
            "timed_out": timed_out,
            "session_id": self.id,
        }

    def read_until(self, prompt_regex: str, timeout: float | None = None) -> str:
        """Block until ``prompt_regex`` (a regex) is seen on stdout. Returns
        all output up to and including the match. Used for interactive flows
        (waiting for ``msf6 >`` after launching msfconsole, etc.)."""
        if self._closed:
            raise PTYSessionError(f"Session {self.id} is closed")
        wait = timeout if timeout is not None else self.command_timeout
        try:
            self._child.expect(prompt_regex, timeout=wait)
            return _strip_ansi((self._child.before or "") + (self._child.after or ""))
        except Exception as e:
            raise PTYSessionError(
                f"read_until({prompt_regex!r}) timed out on {self.id}: {e}"
            ) from e
