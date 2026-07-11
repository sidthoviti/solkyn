"""DockerExecutor — execute commands inside a Kali Docker container."""

from __future__ import annotations

import logging
import re
import subprocess

logger = logging.getLogger(__name__)

# ANSI escape code pattern
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

# Default output limits (chars) to prevent context window overflow
DEFAULT_STDOUT_LIMIT = 50_000
DEFAULT_STDERR_LIMIT = 10_000


def strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from text."""
    return _ANSI_RE.sub("", text)


def truncate_output(text: str, limit: int) -> str:
    """Truncate text to limit chars, appending a notice if truncated."""
    if len(text) <= limit:
        return text
    return (
        text[:limit]
        + f"\n... [OUTPUT TRUNCATED — {len(text)} chars, showing first {limit} chars]"
    )


class DockerExecutor:
    """Execute bash commands inside a running Kali Docker container."""

    def __init__(
        self,
        container_name: str,
        timeout: int = 120,
        stdout_limit: int = DEFAULT_STDOUT_LIMIT,
        stderr_limit: int = DEFAULT_STDERR_LIMIT,
    ):
        self.container_name = container_name
        self.timeout = timeout
        self.stdout_limit = stdout_limit
        self.stderr_limit = stderr_limit

    def execute(self, command: str) -> dict:
        """Run a bash command in the container.

        Returns:
            Dict with 'stdout', 'stderr', 'exit_code', and 'timed_out' keys.
        """
        from solkyn.tools.safety import SafetyChecker

        checker = SafetyChecker()
        is_safe, reason = checker.check_command(command)
        if not is_safe:
            logger.warning("Blocked command: %s — %s", command, reason)
            return {
                "stdout": "",
                "stderr": f"BLOCKED: {reason}",
                "exit_code": -1,
                "timed_out": False,
            }

        cmd = [
            "docker", "exec", self.container_name,
            "bash", "-c", command,
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            stdout = truncate_output(strip_ansi(result.stdout), self.stdout_limit)
            stderr = truncate_output(strip_ansi(result.stderr), self.stderr_limit)
            return {
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": result.returncode,
                "timed_out": False,
            }
        except subprocess.TimeoutExpired as e:
            stdout = truncate_output(
                strip_ansi(e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")),
                self.stdout_limit,
            )
            stderr = truncate_output(
                strip_ansi(e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")),
                self.stderr_limit,
            )
            logger.warning(
                "Command timed out after %ds in %s: %s",
                self.timeout, self.container_name, command,
            )
            return {
                "stdout": stdout,
                "stderr": stderr + f"\n[TIMED OUT after {self.timeout}s]",
                "exit_code": -1,
                "timed_out": True,
            }
