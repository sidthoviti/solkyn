"""SolverAgent — the core autonomous pentesting agent loop."""

from __future__ import annotations

import logging
import re
import time

from solkyn.agents.flag_detector import FlagDetector
from solkyn.agents.orchestrator import Orchestrator
from solkyn.agents.prompt_builder import build_solver_prompt, generate_canary
from solkyn.agents.result import AgentResult
from solkyn.agents.solvers import SOLVER_NAMES, get_solver
from solkyn.agents.state import ScanState
from solkyn.config.schema import AgentConfig
from solkyn.core.cost import CostTracker
from solkyn.core.deadline import Deadline
from solkyn.llm.manager import LLMManager
from solkyn.observability.display import RunDisplay
from solkyn.observability.events import EventLogger
from solkyn.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)


class SolverAgent:
    """Autonomous pentesting agent: LLM reasoning + tool execution loop."""

    def __init__(
        self,
        llm_manager: LLMManager,
        tool_registry: ToolRegistry,
        config: AgentConfig | None = None,
        flag_detector: FlagDetector | None = None,
        system_prompt: str | None = None,
        tags: list[str] | None = None,
        display: RunDisplay | None = None,
        event_logger: EventLogger | None = None,
        mode: str = "whitebox",
        cost_tracker: CostTracker | None = None,
        disable_playbooks: bool = False,
        progress_content: str | None = None,
        solver_name: str = "single_loop",
    ):
        self.llm = llm_manager
        self.tools = tool_registry
        self.config = config or AgentConfig()
        self.flag_detector = flag_detector or FlagDetector()
        self._custom_prompt = system_prompt
        self._tags = tags
        self._display = display
        self._events = event_logger
        self._mode = mode if mode in ("blackbox", "greybox", "whitebox") else "whitebox"
        self._cost_tracker = cost_tracker
        self._disable_playbooks = disable_playbooks
        #  content from a previous attempt's progress.md, injected
        # into the system prompt's progress_content Jinja slot so the next
        # attempt picks up where the prior one left off.
        self._progress_content = progress_content
        #  select solver strategy. "single_loop" (default),
        # "single_loop_compact" (adds threshold-triggered compaction),
        # or "hacksynth" ( planner + summarizer dual-LLM).
        if solver_name not in SOLVER_NAMES:
            raise ValueError(
                f"Unknown solver_name: {solver_name!r}. "
                f"Available: {', '.join(SOLVER_NAMES)}"
            )
        self._solver_name = solver_name

    def _capture_evidence_screenshot(self, target_url: str) -> str | None:
        """Take a screenshot of the target for evidence collection.

        Returns the container path of the screenshot, or None on failure.
        """
        screenshot_path = "/tmp/evidence_screenshot.png"
        try:
            result = self.tools.execute_tool(
                "bash_exec",
                {"command": f"python3 /tools/browser_helper.py screenshot '{target_url}' {screenshot_path}"},
            )
            if "Screenshot saved" in result:
                logger.info("Evidence screenshot saved to %s", screenshot_path)
                return screenshot_path
            logger.warning("Screenshot capture returned unexpected result: %s", result[:200])
        except Exception as e:
            logger.warning("Failed to capture evidence screenshot: %s", e)
        return None

    @staticmethod
    def _normalize_command_sig(tool_name: str, args: dict) -> str:
        """Normalize a tool call into a short signature for loop detection.

        For bash_exec, extracts just the base command (curl, ls, find, etc.)
        to detect repetitive patterns even with different arguments.
        """
        if tool_name == "bash_exec":
            cmd = args.get("command", "")
            # Extract the first word/command from the shell command
            base_cmd = cmd.strip().split()[0] if cmd.strip() else "empty"
            # For curl, also check if it's GET vs POST
            if base_cmd == "curl" and "-X POST" in cmd:
                return "bash_exec:curl_post"
            if base_cmd == "python3" or base_cmd == "python":
                return "bash_exec:python"
            return f"bash_exec:{base_cmd}"
        return f"{tool_name}:{str(args)[:80]}"

    def run(
        self,
        target_url: str,
        description: str,
        scan_dir: str | None = None,
        files: list[str] | None = None,
        file_contents: dict[str, str] | None = None,
    ) -> AgentResult:
        """Run the agent loop against a target.

        Args:
            target_url: The URL to attack.
            description: Challenge/target description.
            scan_dir: Optional directory for state persistence and logs.
            files: Optional list of relevant filenames for context.
            file_contents: Optional dict of filename → content for key source files.

        Returns:
            AgentResult with success status, flag, and full run data.
        """
        start_time = time.time()

        # ------------------------------------------------------------------
        # Build system prompt + initial user message (mode-dependent).
        # Same as previous.
        # ------------------------------------------------------------------
        #  fresh canary per attempt; embedded in system prompt + reported.
        canary = generate_canary()
        if self._custom_prompt:
            system_prompt = self._custom_prompt
        else:
            prompt_tags = self._tags if self._mode != "blackbox" else None
            prompt_files = files if self._mode == "whitebox" else None
            system_prompt = build_solver_prompt(
                target_url=target_url,
                description=description,
                tags=prompt_tags,
                files=prompt_files,
                mode=self._mode,
                canary=canary,
                disable_playbooks=self._disable_playbooks,
                progress_content=self._progress_content,
            )

        if self._mode == "blackbox":
            user_content = (
                f"## Target\n- URL: {target_url}\n\n"
                "You have no prior information about this target. Reconnoitre, identify the "
                "technology stack, enumerate endpoints, find vulnerabilities, exploit, and "
                "capture the flag. Use any playbook from the system prompt as relevant."
            )
        else:
            user_content = f"## Target\n- URL: {target_url}\n- Description: {description}"
            if self._tags:
                user_content += f"\n- Engagement scope tags: {', '.join(self._tags)}"

        if self._mode == "whitebox" and files:
            user_content += (
                "\n\n## Target Application Source Files (REFERENCE ONLY — NOT on your local disk)\n"
                "These are the target app's source files. Use them to understand endpoints, "
                "parameters, and vulnerabilities. Then attack the target URL remotely.\n"
            )
            user_content += "\n".join(f"- {f}" for f in files)

        if self._mode == "whitebox" and file_contents:
            user_content += (
                "\n\n## Key Source File Contents\n"
                "Below are the contents of critical source files. Study them carefully to "
                "identify secrets, API endpoints, authentication logic, and vulnerabilities.\n"
            )
            for fname, content in file_contents.items():
                safe_content = re.sub(
                    r'(?im)^([A-Z_]*FLAG[A-Z_]*\s*=\s*)["\']?[^"\'\n\r]*["\']?',
                    r"\1<REDACTED>",
                    content,
                )
                user_content += f"\n### {fname}\n```\n{safe_content}\n```\n"

        # ------------------------------------------------------------------
        # Init solver ( /  factory) + state for persistence.
        # ------------------------------------------------------------------
        tool_schemas = self.tools.get_schemas()
        solver = get_solver(
            self._solver_name,
            llm_manager=self.llm,
            tool_schemas=tool_schemas,
            flag_detector=self.flag_detector,
            tags=self._tags,
            max_nudges=3,
        )
        solver.initialize(system_prompt)
        solver.inject_message("user", user_content)

        state = None
        if scan_dir:
            state = ScanState(
                scan_id=scan_dir.split("/")[-1] if "/" in scan_dir else scan_dir,
                target_url=target_url,
                description=description,
                max_iterations=self.config.max_iterations,
            )

        # ------------------------------------------------------------------
        # Delegate the loop to the strategy-agnostic Orchestrator.
        #  pass deadline + cost tracker for time/cost limits.
        # ------------------------------------------------------------------
        deadline: Deadline | None = None
        if self.config.max_time_seconds is not None:
            deadline = Deadline(max_seconds=self.config.max_time_seconds)
            # Wire backoff sleeps to be excluded from the budget.
            self.llm.set_deadline(deadline)

        orchestrator = Orchestrator(
            tools=self.tools,
            flag_detector=self.flag_detector,
            max_iterations=self.config.max_iterations,
            display=self._display,
            events=self._events,
            deadline=deadline,
            cost_tracker=self._cost_tracker,
            max_cost_usd=self.config.max_cost_usd,
            model_name=self.llm.model if self._cost_tracker else None,
        )
        orch_result = orchestrator.run(solver, scan_dir=scan_dir, state=state)

        flags_found = orch_result.flags_found
        iteration = orch_result.iterations
        tool_calls_log = orch_result.tool_calls_log

        if orch_result.exit_reason == "error":
            elapsed = time.time() - start_time
            llm_usage = self.llm.get_usage()
            return AgentResult(
                success=False,
                flag=flags_found[0] if flags_found else None,
                iterations=iteration,
                messages=getattr(solver, "messages", []),
                tool_calls_log=tool_calls_log,
                total_time=round(elapsed, 2),
                token_usage=llm_usage,
                error=orch_result.error,
                exit_reason=orch_result.exit_reason,
                cost_usd=self._cost_tracker.total_usd if self._cost_tracker else None,
                canary=canary,
                conversation=solver.serialize_conversation(),
                cache_read_input_tokens=llm_usage.get("cache_read_input_tokens", 0),
                cache_creation_input_tokens=llm_usage.get("cache_creation_input_tokens", 0),
                upstream_cost_usd=llm_usage.get("upstream_cost_usd"),
                refusal_count=llm_usage.get("refusal_count", 0),
            )

        elapsed = time.time() - start_time
        flag = flags_found[0] if flags_found else None

        evidence_screenshot = None
        if flag:
            evidence_screenshot = self._capture_evidence_screenshot(target_url)

        if scan_dir and state:
            state.flags = list(set(flags_found))
            state.phase = "complete"
            state.save(scan_dir)

        logger.info(
            "Agent finished: %d iterations, %.1fs, flag=%s",
            iteration, elapsed, "found" if flag else "not found",
        )

        return AgentResult(
            success=flag is not None,
            flag=flag,
            iterations=iteration,
            messages=getattr(solver, "messages", []),
            tool_calls_log=tool_calls_log,
            total_time=round(elapsed, 2),
            token_usage=self.llm.get_usage(),
            evidence_screenshot=evidence_screenshot,
            exit_reason=orch_result.exit_reason,
            cost_usd=self._cost_tracker.total_usd if self._cost_tracker else None,
            canary=canary,
            conversation=solver.serialize_conversation(),
            cache_read_input_tokens=self.llm.total_cache_read_input_tokens,
            cache_creation_input_tokens=self.llm.total_cache_creation_input_tokens,
            upstream_cost_usd=self.llm.total_upstream_cost_usd,
            refusal_count=self.llm.refusal_count,
        )
