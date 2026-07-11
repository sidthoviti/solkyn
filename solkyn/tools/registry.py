"""Tool registry — register tools and dispatch calls for LLM function calling."""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Callable

from solkyn.llm.tools import make_tool_schema

logger = logging.getLogger(__name__)

# Patterns that indicate the model is trying to write a file via bash instead of file_write
_HEREDOC_PATTERN = re.compile(
    r"cat\s+>.*<<\s*['\"]?\w+['\"]?|cat\s*<<\s*['\"]?\w+['\"]?\s*>",
    re.IGNORECASE,
)
_ECHO_REDIRECT_PATTERN = re.compile(
    r"echo\s+['\"].*['\"].*>\s*/",
    re.IGNORECASE | re.DOTALL,
)
_FILE_WRITE_BASH_PATTERN = re.compile(
    r"file_write\s*\{|file_write\s*\(",
    re.IGNORECASE,
)


class ToolRegistry:
    """Registry of tools available to the LLM agent."""

    def __init__(self) -> None:
        self._tools: dict[str, _RegisteredTool] = {}

    def register(
        self,
        name: str,
        description: str,
        parameters: dict,
        handler: Callable[..., str],
    ) -> None:
        """Register a tool.

        Args:
            name: Unique tool name (e.g., 'bash_exec').
            description: Description shown to the LLM.
            parameters: JSON Schema for the tool's parameters.
            handler: Callable that accepts **kwargs matching parameters and returns a string.
        """
        self._tools[name] = _RegisteredTool(
            name=name,
            description=description,
            parameters=parameters,
            handler=handler,
        )
        logger.debug("Registered tool: %s", name)

    def get_schemas(self) -> list[dict]:
        """Return all tool schemas in OpenAI function-calling format."""
        return [
            make_tool_schema(t.name, t.description, t.parameters)
            for t in self._tools.values()
        ]

    def execute_tool(self, name: str, arguments: dict[str, Any]) -> str:
        """Execute a registered tool by name.

        Args:
            name: Tool name.
            arguments: Dict of arguments matching the tool's parameter schema.

        Returns:
            Tool output as a string.

        Raises:
            KeyError: If the tool is not registered.
        """
        if name not in self._tools:
            raise KeyError(f"Unknown tool: {name}. Available: {', '.join(self._tools)}")

        tool = self._tools[name]
        logger.info("Executing tool: %s(%s)", name, json.dumps(arguments, default=str)[:200])
        return tool.handler(**arguments)


class _RegisteredTool:
    """Internal representation of a registered tool."""

    __slots__ = ("name", "description", "parameters", "handler")

    def __init__(
        self,
        name: str,
        description: str,
        parameters: dict,
        handler: Callable[..., str],
    ) -> None:
        self.name = name
        self.description = description
        self.parameters = parameters
        self.handler = handler


def create_default_tools(executor: Any) -> ToolRegistry:
    """Create a ToolRegistry with the 3 core tools wired to a DockerExecutor.

    Args:
        executor: A DockerExecutor instance.

    Returns:
        ToolRegistry with bash_exec, file_read, file_write registered.
    """
    registry = ToolRegistry()

    # --- bash_exec ---
    def bash_exec(command: str, **_kwargs: Any) -> str:
        # Silently ignore unknown kwargs (e.g. some models pass `timeout`,
        # `cwd`, `env` even though we don't expose them in the schema).
        # Intercept file-writing patterns that should use the file_write tool
        if _HEREDOC_PATTERN.search(command) or _FILE_WRITE_BASH_PATTERN.search(command):
            return (
                "ERROR: Do NOT use cat <<EOF, cat <<'EOF', or heredocs in bash to write files. "
                "Use the `file_write` tool instead — it handles special characters correctly.\n"
                "Example: call file_write with path='/tmp/exploit.py' and content='...your code...'"
            )
        if _ECHO_REDIRECT_PATTERN.search(command) and len(command) > 200:
            return (
                "ERROR: For writing multi-line content to files, use the `file_write` tool "
                "instead of echo with redirects. It's more reliable for exploit scripts.\n"
                "Example: call file_write with path='/tmp/exploit.py' and content='...your code...'"
            )

        result = executor.execute(command)
        parts = []
        if result["stdout"]:
            parts.append(result["stdout"])
        if result["stderr"]:
            parts.append(f"STDERR: {result['stderr']}")
        if result["timed_out"]:
            parts.append("[COMMAND TIMED OUT]")
        if not parts:
            parts.append(f"(exit code {result['exit_code']})")
        return "\n".join(parts)

    registry.register(
        name="bash_exec",
        description=(
            "Execute a bash command in the Kali Linux container. "
            "Available tools:\n"
            "- RECON: nmap, whatweb, nikto, gobuster, ffuf, dirb, wpscan\n"
            "- SQLI: sqlmap\n"
            "- XSS: xsstrike, dalfox\n"
            "- SCANNING: nuclei, nikto\n"
            "- HTTP: curl, wget, httpie\n"
            "- BROWSER: python3 /tools/browser_helper.py (headless Chromium via Playwright)\n"
            "- EXPLOITS: searchsploit, msfconsole, python3 (requests, pwntools, bs4)\n"
            "- UTILS: jq, socat, base64, openssl, xxd, john, hashcat\n"
            "Use specialized tools (sqlmap, ffuf, nuclei) BEFORE writing custom scripts. "
            "Do NOT use cat <<EOF or heredocs to write files — use the file_write tool instead."
        ),
        parameters={
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The bash command to execute.",
                },
            },
            "required": ["command"],
        },
        handler=bash_exec,
    )

    # --- file_read ---
    def file_read(path: str) -> str:
        result = executor.execute(f"cat {path}")
        if result["exit_code"] != 0:
            return f"Error reading {path}: {result['stderr']}"
        return result["stdout"]

    registry.register(
        name="file_read",
        description="Read a file from the Kali container filesystem.",
        parameters={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute path to the file to read.",
                },
            },
            "required": ["path"],
        },
        handler=file_read,
    )

    # --- file_write ---
    def file_write(path: str, content: str) -> str:
        # Use base64 encoding to avoid all quoting/escaping issues
        import base64

        encoded = base64.b64encode(content.encode()).decode()
        result = executor.execute(f"printf '%s' {encoded} | base64 -d > {path}")
        if result["exit_code"] != 0:
            return f"Error writing {path}: {result['stderr']}"
        return f"Written {len(content)} bytes to {path}"

    registry.register(
        name="file_write",
        description=(
            "Write content to a file in the Kali container. "
            "ALWAYS use this tool (not bash heredocs/echo) to create scripts, exploits, "
            "and config files. Write to /tmp/ directory."
        ),
        parameters={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute path to the file to write.",
                },
                "content": {
                    "type": "string",
                    "description": "Content to write to the file.",
                },
            },
            "required": ["path", "content"],
        },
        handler=file_write,
    )

    return registry


def register_pty_tools(registry: ToolRegistry, pty_executor: Any) -> ToolRegistry:
    """Register the  PTY tools (``pty_open`` / ``pty_run`` / ``pty_close``)
    into ``registry`` and return it. Idempotent on the registry contents — the
    caller decides whether ``bash_exec`` stays available alongside.

    The ``pty_executor`` is anything implementing ``open_session()``,
    ``run_in_session(id, cmd, timeout?)``, and ``close_session(id)`` — i.e.
    :class:`solkyn.tools.pty_executor.PTYExecutor`.
    """

    def pty_open(session_id: str | None = None, **_kwargs: Any) -> str:
        try:
            sid = pty_executor.open_session(session_id)
            return f"OK: pty session {sid} opened (use this id with pty_run / pty_close)"
        except Exception as e:
            return f"ERROR opening pty session: {e}"

    def pty_run(session_id: str, command: str, timeout: float | None = None,
                **_kwargs: Any) -> str:
        try:
            res = pty_executor.run_in_session(session_id, command, timeout=timeout)
        except Exception as e:
            return f"ERROR running in {session_id}: {e}"
        out = res.get("output", "")
        if res.get("timed_out"):
            return out  # already includes the [TIMED OUT ...] marker
        return out or f"(no output, session {session_id} alive)"

    def pty_close(session_id: str, **_kwargs: Any) -> str:
        try:
            existed = pty_executor.close_session(session_id)
        except Exception as e:
            return f"ERROR closing {session_id}: {e}"
        return f"OK: pty session {session_id} closed" if existed else \
               f"WARN: no such pty session {session_id}"

    registry.register(
        name="pty_open",
        description=(
            "Open a NEW persistent shell session in the Kali container. "
            "Use when you need state to persist across commands (cd, export, "
            "source, interactive CLIs like mysql/msfconsole, or background "
            "listeners like `nc -lvnp 8888 &`). Returns a session_id you must "
            "pass to pty_run and pty_close. Prefer bash_exec for one-shot "
            "stateless commands — sessions are heavier."
        ),
        parameters={
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": (
                        "Optional explicit id (e.g. 'listener'). Auto-assigned "
                        "when omitted."
                    ),
                },
            },
            "required": [],
        },
        handler=pty_open,
    )

    registry.register(
        name="pty_run",
        description=(
            "Run a command in an existing pty session opened by pty_open. "
            "State (cwd, env, background jobs, interactive CLIs) persists "
            "across calls in the same session. On timeout the command is "
            "interrupted with Ctrl-C but the session stays alive."
        ),
        parameters={
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "The id returned by pty_open.",
                },
                "command": {
                    "type": "string",
                    "description": "The command to execute in the session.",
                },
                "timeout": {
                    "type": "number",
                    "description": (
                        "Per-command timeout in seconds (default: session "
                        "default). Useful for long listeners."
                    ),
                },
            },
            "required": ["session_id", "command"],
        },
        handler=pty_run,
    )

    registry.register(
        name="pty_close",
        description=(
            "Close a pty session. Always close sessions when finished to "
            "free resources and avoid hitting the session pool cap."
        ),
        parameters={
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "The id returned by pty_open.",
                },
            },
            "required": ["session_id"],
        },
        handler=pty_close,
    )

    return registry
