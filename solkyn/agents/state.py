"""Scan state — persistence for crash recovery and logging."""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class ScanState:
    """Persistent state for a running scan."""

    scan_id: str
    target_url: str
    description: str
    phase: str = "init"
    iterations: int = 0
    max_iterations: int = 60
    flags: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    tool_calls: list[dict] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    token_usage: dict = field(default_factory=lambda: {"input_tokens": 0, "output_tokens": 0})

    def save(self, scan_dir: str | Path) -> None:
        """Save state to scan_dir/state.json."""
        path = Path(scan_dir)
        path.mkdir(parents=True, exist_ok=True)
        state_file = path / "state.json"
        with open(state_file, "w") as f:
            json.dump(asdict(self), f, indent=2, default=str)

    @classmethod
    def load(cls, scan_dir: str | Path) -> ScanState:
        """Load state from scan_dir/state.json."""
        state_file = Path(scan_dir) / "state.json"
        with open(state_file) as f:
            data = json.load(f)
        return cls(**data)

    def append_log(self, scan_dir: str | Path, message: dict) -> None:
        """Append a message to the JSONL log file."""
        path = Path(scan_dir) / "logs"
        path.mkdir(parents=True, exist_ok=True)
        log_file = path / "solver.jsonl"
        with open(log_file, "a") as f:
            f.write(json.dumps(message, default=str) + "\n")
