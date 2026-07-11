"""Safety checker for commands executed in the Kali container."""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

# Patterns that are always blocked (compiled regexes)
_BLOCKED_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Fork bombs
    (re.compile(r":\(\)\s*\{.*\|.*&\s*\}\s*;?\s*:"), "fork bomb detected"),
    (re.compile(r"\.\(\)\s*\{.*\|.*&\s*\}\s*;?\s*\."), "fork bomb detected"),
    # Disk formatting
    (re.compile(r"\bmkfs\b"), "disk formatting command"),
    # Shutdown / reboot
    (re.compile(r"\b(shutdown|reboot|poweroff|halt|init\s+[06])\b"), "shutdown/reboot command"),
    # rm -rf / (but NOT rm -rf /workspace/*)
    (re.compile(r"\brm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)?(-[a-zA-Z]*r[a-zA-Z]*\s+)?/\s*$"), "rm -rf / (root filesystem)"),
    (re.compile(r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+)?(-[a-zA-Z]*f[a-zA-Z]*\s+)?/\s*$"), "rm -rf / (root filesystem)"),
    (re.compile(r"\brm\s+-[a-zA-Z]*rf[a-zA-Z]*\s+/\s*$"), "rm -rf / (root filesystem)"),
    # Docker commands (prevent container escape) — match 'docker' as a command,
    # not as part of hostnames like 'host.docker.internal'
    (re.compile(r"(?<!\.)docker\s"), "docker command (container escape prevention)"),
    # Direct writes to critical system paths
    (re.compile(r">\s*/etc/passwd"), "overwriting /etc/passwd"),
    (re.compile(r">\s*/etc/shadow"), "overwriting /etc/shadow"),
]


class SafetyChecker:
    """Check commands for dangerous patterns before execution."""

    def check_command(self, command: str) -> tuple[bool, str]:
        """Check if a command is safe to execute.

        Args:
            command: The bash command string.

        Returns:
            Tuple of (is_safe, reason). If safe, reason is empty string.
        """
        for pattern, reason in _BLOCKED_PATTERNS:
            if pattern.search(command):
                logger.warning("Safety check BLOCKED: %r — %s", command, reason)
                return False, reason

        return True, ""
