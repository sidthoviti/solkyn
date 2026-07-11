#!/usr/bin/env python3
"""Sequential, resumable, multi-model sweep runner for the v1 XBOW release.

Pre-registered in docs/methodology.md (§4, §8). One model at a time; for
each model, runs every (challenge × attempt) tuple that has not yet
landed in the model's manifest. Idempotent on re-launch: a fresh
invocation reads the manifest and skips already-completed work.

Why a sweep wrapper instead of just calling run_challenges.py with
--attempts N: run_challenges.py's --attempts is the *chained* pass@N
flow (progress.md handoff between attempts). For the headline pass@k
result we want INDEPENDENT attempts — each rebuilds the challenge with
a fresh flag and starts from a clean conversation. The wrapper drives
n independent invocations of `run_challenges.py --attempts 1
--no-generate-progress`.

Usage
-----

    # Per-model launch
    python scripts/run_full_sweep.py \\
        --model azure-gpt54 \\
        --leg whitebox \\
        --attempts 3 \\
        --mode whitebox \\
        --max-iterations 25 \\
        --max-iterations-l3 50 \\
        --solver single_loop_compact

    # Resume after interruption (same command, picks up where it left off)
    python scripts/run_full_sweep.py ...same args...

    # Smoke / sanity (one challenge × all models — use scripts/smoke_all_models.py)

Each per-model leg produces:

    scans/full_sweep_v1/{model}-{leg}/
        manifest.jsonl          # one JSON line per completed (cid, attempt)
        _run_metadata.json      # leg config, sweep command, git SHA, start time
        XBEN-NNN-NN/
            <existing per-attempt dirs created by run_challenges.py>

Resumability rules
------------------

A tuple (challenge_id, attempt_idx) is considered DONE if the manifest
records it with `exit_reason` in:
    {flag_found, max_iterations, no_tool_calls, time_limit, cost_limit}
i.e. all honest sweep terminations. Tuples with `exit_reason=error`
(infrastructure / API failure / etc.) are retried up to MAX_RETRIES
before being recorded as permanent infrastructure failures (also
marked in manifest).

The manifest is the source of truth. Per-attempt directories under
scans/{challenge_id}/ may exist from past sweeps; the manifest is what
this runner consults.
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from solkyn.platforms.xbow import XBOWPlatform  # noqa: E402

logger = logging.getLogger("solkyn.full_sweep")

MAX_RETRIES = 2  # retries for exit_reason=error (infrastructure)
HONEST_TERMINATIONS = frozenset(
    {"flag_found", "max_iterations", "no_tool_calls", "time_limit", "cost_limit"}
)


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------


class Manifest:
    """Append-only JSONL log of completed (challenge_id, attempt_idx) tuples."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._entries: list[dict] = []
        if path.exists():
            for line in path.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    self._entries.append(json.loads(line))
                except json.JSONDecodeError:
                    logger.warning("Skipping malformed manifest line: %s", line[:80])

    def is_done(self, cid: str, attempt: int) -> bool:
        """A tuple is done if any honest termination has been recorded."""
        for e in self._entries:
            if (
                e.get("challenge_id") == cid
                and e.get("attempt_idx") == attempt
                and e.get("exit_reason") in HONEST_TERMINATIONS
            ):
                return True
        return False

    def error_retries_used(self, cid: str, attempt: int) -> int:
        """Count error-tagged manifest entries for this tuple."""
        return sum(
            1
            for e in self._entries
            if e.get("challenge_id") == cid
            and e.get("attempt_idx") == attempt
            and e.get("exit_reason") == "error"
        )

    def is_permanently_failed(self, cid: str, attempt: int) -> bool:
        for e in self._entries:
            if (
                e.get("challenge_id") == cid
                and e.get("attempt_idx") == attempt
                and e.get("status") == "permanent_infra_failure"
            ):
                return True
        return False

    def append(self, entry: dict) -> None:
        entry["recorded_at"] = time.time()
        with self.path.open("a") as f:
            f.write(json.dumps(entry) + "\n")
        self._entries.append(entry)

    def stats(self) -> dict:
        per_cid_max_attempt: dict[str, int] = {}
        solves = 0
        total_cost = 0.0
        for e in self._entries:
            cid = e.get("challenge_id")
            if not cid:
                continue
            per_cid_max_attempt[cid] = max(
                per_cid_max_attempt.get(cid, 0), e.get("attempt_idx", 0)
            )
            if e.get("success") is True:
                solves += 1
            total_cost += e.get("cost_usd") or 0.0
        return {
            "completed_attempts": len(self._entries),
            "unique_challenges_touched": len(per_cid_max_attempt),
            "solves": solves,
            "cost_usd_so_far": round(total_cost, 4),
        }


# ---------------------------------------------------------------------------
# Per-attempt orchestration
# ---------------------------------------------------------------------------


def _newest_attempt_dir_for(cid: str, output_root: Path) -> Path | None:
    """Return the most-recently-created attempt dir under output_root/{cid}/."""
    challenge_dir = output_root / cid
    if not challenge_dir.exists():
        return None
    attempts = [
        p
        for p in challenge_dir.iterdir()
        if p.is_dir() and "attempt_" in p.name and (p / "stats.json").exists()
    ]
    if not attempts:
        return None
    # Lexicographic sort works because dir names start with timestamp YYYYMMDD_HHMMSS
    return sorted(attempts)[-1]


def _run_one_attempt(
    cid: str,
    *,
    provider: str,
    config_path: Path,
    output_root: Path,
    mode: str,
    max_iterations: int,
    max_iterations_l3: int | None,
    solver: str,
    verbose: bool,
) -> dict:
    """Invoke scripts/run_challenges.py for a single (cid, 1 independent
    attempt). Returns the parsed stats.json of the resulting attempt
    directory, plus 'attempt_dir' and 'returncode'.
    """
    cmd: list[str] = [
        sys.executable,
        str(PROJECT_ROOT / "scripts/run_challenges.py"),
        "-c", cid,
        "--config", str(config_path),
        "--provider", provider,
        "--mode", mode,
        "--solver", solver,
        "--max-iterations", str(max_iterations),
        "--attempts", "1",
        "--no-generate-progress",
        "--output", str(output_root),
    ]
    if max_iterations_l3 is not None:
        cmd.extend(["--max-iterations-l3", str(max_iterations_l3)])
    if verbose:
        cmd.append("-v")

    logger.info("LAUNCH %s", " ".join(cmd))
    started = time.time()
    proc = subprocess.run(cmd, capture_output=False, text=True)
    elapsed = time.time() - started

    # Find the attempt dir produced by this invocation.
    attempt_dir = _newest_attempt_dir_for(cid, output_root)
    stats: dict = {}
    if attempt_dir is not None and (attempt_dir / "stats.json").exists():
        try:
            stats = json.loads((attempt_dir / "stats.json").read_text())
        except Exception as e:  # noqa: BLE001
            logger.error("Failed to parse stats.json for %s: %s", cid, e)
    else:
        logger.warning(
            "No attempt dir / stats.json produced for %s (rc=%d, elapsed=%.1fs)",
            cid, proc.returncode, elapsed,
        )

    return {
        "stats": stats,
        "attempt_dir": str(attempt_dir) if attempt_dir else None,
        "returncode": proc.returncode,
        "wall_seconds": round(elapsed, 2),
    }


# ---------------------------------------------------------------------------
# Per-leg driver
# ---------------------------------------------------------------------------


def run_leg(
    *,
    provider: str,
    leg_name: str,
    attempts: int,
    challenge_ids: list[str],
    config_path: Path,
    base_output: Path,
    mode: str,
    max_iterations: int,
    max_iterations_l3: int | None,
    solver: str,
    verbose: bool,
) -> int:
    """Run a single per-model leg of the sweep. Returns total tuples
    completed in this invocation (excluding skips for already-done)."""
    leg_dir = base_output / f"{provider}-{leg_name}"
    leg_dir.mkdir(parents=True, exist_ok=True)
    manifest = Manifest(leg_dir / "manifest.jsonl")
    sweep_output_root = leg_dir  # per-challenge dirs land here

    # Drop a run-metadata file (first invocation only — appended on resume).
    metadata_path = leg_dir / "_run_metadata.jsonl"
    git_sha = _git_sha()
    with metadata_path.open("a") as f:
        f.write(
            json.dumps(
                {
                    "started_at": time.time(),
                    "provider": provider,
                    "leg_name": leg_name,
                    "attempts": attempts,
                    "challenges": len(challenge_ids),
                    "mode": mode,
                    "max_iterations": max_iterations,
                    "max_iterations_l3": max_iterations_l3,
                    "solver": solver,
                    "git_sha": git_sha,
                    "config": str(config_path),
                }
            )
            + "\n"
        )

    initial_stats = manifest.stats()
    logger.info(
        "Leg %s/%s starting. Manifest: %d entries, %d solves so far, $%.2f spent.",
        provider, leg_name, initial_stats["completed_attempts"],
        initial_stats["solves"], initial_stats["cost_usd_so_far"],
    )

    completed = 0
    for cid in challenge_ids:
        for attempt_idx in range(1, attempts + 1):
            if manifest.is_done(cid, attempt_idx):
                logger.info("SKIP %s attempt %d/%d (already complete)",
                            cid, attempt_idx, attempts)
                continue
            if manifest.is_permanently_failed(cid, attempt_idx):
                logger.info("SKIP %s attempt %d/%d (permanent infra fail)",
                            cid, attempt_idx, attempts)
                continue

            for retry in range(MAX_RETRIES + 1):
                already = manifest.error_retries_used(cid, attempt_idx)
                if already >= MAX_RETRIES:
                    manifest.append(
                        {
                            "challenge_id": cid,
                            "attempt_idx": attempt_idx,
                            "status": "permanent_infra_failure",
                            "exit_reason": "error",
                            "error_retries_used": already,
                        }
                    )
                    logger.error(
                        "PERMANENT INFRA FAILURE %s attempt %d/%d "
                        "after %d error retries",
                        cid, attempt_idx, attempts, already,
                    )
                    break

                logger.info(
                    "RUN %s attempt %d/%d (retry %d/%d)",
                    cid, attempt_idx, attempts, retry, MAX_RETRIES,
                )
                result = _run_one_attempt(
                    cid,
                    provider=provider,
                    config_path=config_path,
                    output_root=sweep_output_root,
                    mode=mode,
                    max_iterations=max_iterations,
                    max_iterations_l3=max_iterations_l3,
                    solver=solver,
                    verbose=verbose,
                )
                stats = result["stats"]
                exit_reason = stats.get("exit_reason") or (
                    "error" if not stats else "error"
                )

                entry = {
                    "challenge_id": cid,
                    "attempt_idx": attempt_idx,
                    "exit_reason": exit_reason,
                    "success": stats.get("success", False),
                    "flag_found": stats.get("flag"),
                    "iterations": stats.get("iterations"),
                    "duration_seconds": stats.get("duration_seconds"),
                    "cost_usd": stats.get("cost_usd"),
                    "upstream_cost_usd": stats.get("upstream_cost_usd"),
                    "refusal_count": stats.get("refusal_count"),
                    "attempt_dir": result["attempt_dir"],
                    "subprocess_returncode": result["returncode"],
                    "subprocess_wall_seconds": result["wall_seconds"],
                    "status": "complete" if exit_reason in HONEST_TERMINATIONS else "error_retry",
                }
                manifest.append(entry)
                completed += 1

                if exit_reason in HONEST_TERMINATIONS:
                    s = manifest.stats()
                    logger.info(
                        "OK %s a%d → %s (%s) | cum: %d done, %d solves, $%.2f",
                        cid, attempt_idx, exit_reason,
                        "PASS" if stats.get("success") else "fail",
                        s["completed_attempts"], s["solves"], s["cost_usd_so_far"],
                    )
                    break
                else:
                    logger.warning(
                        "ERROR %s a%d (rc=%d). Will retry %d/%d.",
                        cid, attempt_idx, result["returncode"],
                        retry + 1, MAX_RETRIES,
                    )
    final = manifest.stats()
    logger.info(
        "Leg %s/%s done. Total: %d attempts in manifest, %d solves, $%.2f spent.",
        provider, leg_name, final["completed_attempts"],
        final["solves"], final["cost_usd_so_far"],
    )
    return completed


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _git_sha() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=2,
        )
        return out.stdout.strip() if out.returncode == 0 else "unknown"
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"


def _resolve_challenges(args: argparse.Namespace) -> list[str]:
    platform = XBOWPlatform()
    if args.challenges:
        return list(args.challenges)
    all_cids = platform.list_challenges()
    if args.level:
        all_cids = [
            cid for cid in all_cids
            if platform.load_challenge(cid).level == str(args.level)
        ]
    return list(all_cids)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sequential, resumable multi-model XBOW sweep runner (v1)."
    )
    parser.add_argument(
        "--model", required=True,
        help="Provider key in configs/default.yaml models.providers (one only — "
             "for multi-model, run this script once per model)."
    )
    parser.add_argument(
        "--leg", default="whitebox",
        help="Label for this leg; appended to output dir name. Convention: "
             "'whitebox' (default) / 'blackbox' / 'greybox' / 'chained-pass3'.",
    )
    parser.add_argument(
        "--attempts", type=int, default=3,
        help="Number of independent attempts per challenge (default 3).",
    )
    parser.add_argument(
        "--mode", choices=["whitebox", "greybox", "blackbox"], default="whitebox",
        help="Forwarded to run_challenges.py --mode.",
    )
    parser.add_argument(
        "--max-iterations", type=int, default=25,
        help="Per-attempt iteration cap (L1/L2). Default 25.",
    )
    parser.add_argument(
        "--max-iterations-l3", type=int, default=50,
        help="Iteration cap for L3 challenges. Default 50.",
    )
    parser.add_argument(
        "--solver", default="single_loop_compact",
        choices=["single_loop", "single_loop_compact", "hacksynth"],
        help="Solver strategy. Default single_loop_compact (selected solver).",
    )
    parser.add_argument(
        "--config", default="configs/default.yaml",
        help="Path to YAML config.",
    )
    parser.add_argument(
        "--output", default="scans/full_sweep_v1",
        help="Root output directory.",
    )
    parser.add_argument(
        "-c", "--challenge", dest="challenges", action="append",
        help="Run a specific challenge (repeatable). Default: all 104.",
    )
    parser.add_argument(
        "--level", type=int, help="Restrict to a specific level (1/2/3).",
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)-22s %(levelname)-5s %(message)s",
        datefmt="%H:%M:%S",
    )

    config_path = PROJECT_ROOT / args.config
    if not config_path.exists():
        logger.error("Config not found: %s", config_path)
        return 2

    if not shutil.which("docker"):
        logger.error("docker not on PATH; sweep requires docker for the Kali container")
        return 2

    challenges = _resolve_challenges(args)
    logger.info(
        "Sweep plan: provider=%s leg=%s attempts=%d mode=%s solver=%s "
        "max_iter=%d/%dL3 challenges=%d",
        args.model, args.leg, args.attempts, args.mode, args.solver,
        args.max_iterations, args.max_iterations_l3, len(challenges),
    )

    completed = run_leg(
        provider=args.model,
        leg_name=args.leg,
        attempts=args.attempts,
        challenge_ids=challenges,
        config_path=config_path,
        base_output=PROJECT_ROOT / args.output,
        mode=args.mode,
        max_iterations=args.max_iterations,
        max_iterations_l3=args.max_iterations_l3,
        solver=args.solver,
        verbose=args.verbose,
    )
    logger.info("This invocation completed %d new attempts.", completed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
