"""AgentResult — dataclass for solver agent run results."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AgentResult:
    """Result from a solver agent run."""

    success: bool
    flag: str | None = None
    findings: list[dict] = field(default_factory=list)
    iterations: int = 0
    messages: list[dict] = field(default_factory=list)
    tool_calls_log: list[dict] = field(default_factory=list)
    total_time: float = 0.0
    token_usage: dict = field(default_factory=lambda: {"input_tokens": 0, "output_tokens": 0})
    error: str | None = None
    evidence_screenshot: str | None = None  # Container path to screenshot taken on success
    #  orchestrator exit reason ("flag_found", "max_iterations",
    # "no_tool_calls", "time_limit", "cost_limit", "error"). None for
    # callers that bypass the orchestrator (legacy tests).
    exit_reason: str | None = None
    cost_usd: float | None = None
    #  per-run canary string embedded in the system prompt and saved
    # into stats/report. Used to detect training-data leakage if traces are
    # ever published. None for callers that bypass system-prompt building.
    canary: str | None = None
    #  full conversation trace as returned by
    # ``BaseSolver.serialize_conversation()``. Either ``{"format": "flat",
    # "messages": [...]}`` or ``{"format": "nested", "turns": [...]}``.
    # Empty dict for callers that bypass the orchestrator.
    conversation: dict = field(default_factory=dict)
    #  paper-grade auxiliary metrics surfaced from LLMManager.
    cache_read_input_tokens: int = 0
    cache_creation_input_tokens: int = 0
    upstream_cost_usd: float | None = None
    refusal_count: int = 0
