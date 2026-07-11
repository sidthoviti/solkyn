"""Per-attempt directory layout.

Each invocation of `run_challenge()` writes its output into a fresh
attempt directory at::

    scans/{challenge_id}/{YYYYMMDD_HHMMSS}_attempt_{N}/

Files written by this module + the orchestrator + reporting layer:

* `config.json`       — model, solver, mode, max_iterations, max_cost,
                        max_time, expected_flag, tags (this module).
* `stats.json`        — tokens, cost_usd, duration, iterations,
                        status/exit_reason, success, flag (this module).
* `conversation.json` — full message history (this module).
* `state.json`        — `ScanState.save()` (existing).
* `logs/solver.jsonl` — `ScanState.append_log()` (existing).
* `evidence.png`      — copied from container on success (existing).
* `report.md`         — `solkyn.reporting` ( placeholder).

The historical `scans/results-{scan_id}.json` global summary is
preserved verbatim (written by `scripts/run_challenges.py`) so any
downstream tooling keeps working.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

# Pattern for matching existing attempt dirs to compute the next index.
_ATTEMPT_DIR_RE = re.compile(r"^\d{8}_\d{6}_attempt_(\d+)$")


def next_attempt_number(challenge_dir: Path) -> int:
    """Return the next attempt number (1-based) for `challenge_dir`."""
    if not challenge_dir.exists():
        return 1
    highest = 0
    for child in challenge_dir.iterdir():
        if not child.is_dir():
            continue
        m = _ATTEMPT_DIR_RE.match(child.name)
        if m:
            highest = max(highest, int(m.group(1)))
    return highest + 1


def create_attempt_dir(base_output: str | Path, challenge_id: str) -> Path:
    """Create and return a fresh attempt directory.

    Layout: `{base_output}/{challenge_id}/{YYYYMMDD_HHMMSS}_attempt_{N}/`.
    Caller is responsible for any further subdirectory creation.
    """
    challenge_dir = Path(base_output) / challenge_id
    challenge_dir.mkdir(parents=True, exist_ok=True)
    n = next_attempt_number(challenge_dir)
    ts = time.strftime("%Y%m%d_%H%M%S", time.localtime())
    attempt_dir = challenge_dir / f"{ts}_attempt_{n}"
    attempt_dir.mkdir(parents=True, exist_ok=False)
    return attempt_dir


def write_config_json(attempt_dir: Path, config: dict[str, Any]) -> Path:
    """Write `config.json` (model / solver / mode / limits / expected flag)."""
    path = attempt_dir / "config.json"
    path.write_text(json.dumps(config, indent=2, default=str))
    return path


def write_stats_json(attempt_dir: Path, stats: dict[str, Any]) -> Path:
    """Write `stats.json` (tokens / cost / duration / iterations / status)."""
    path = attempt_dir / "stats.json"
    path.write_text(json.dumps(stats, indent=2, default=str))
    return path


def write_conversation_json(
    attempt_dir: Path,
    messages_or_trace: list[dict[str, Any]] | dict[str, Any],
) -> Path:
    """Write `conversation.json` (the full LLM message history).

    Accepts either:

    * a flat ``list[dict]`` of messages (legacy callers) — wrapped as
      ``{"format": "flat", "messages": [...]}``;
    * a full trace dict from :meth:`BaseSolver.serialize_conversation`
      (, includes the ``"format"`` key) — written as-is. The
      ``nested`` shape is used by the HackSynth solver.
    """
    if isinstance(messages_or_trace, dict) and "format" in messages_or_trace:
        trace = messages_or_trace
    else:
        trace = {"format": "flat", "messages": messages_or_trace}
    path = attempt_dir / "conversation.json"
    path.write_text(
        json.dumps(trace, indent=2, default=_json_default),
    )
    return path


def _json_default(obj: Any) -> Any:
    if is_dataclass(obj):
        return asdict(obj)
    return str(obj)
