"""Benchmark runner — orchestrate challenge lifecycle and collect results."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

from solkyn.platforms.xbow import XBOWPlatform

logger = logging.getLogger(__name__)


@dataclass
class BenchmarkResult:
    """Result from running a single benchmark challenge."""

    challenge_id: str
    name: str
    level: str
    tags: list[str]
    success: bool
    flag_expected: str
    flag_found: str | None
    iterations: int
    time_seconds: float
    cost_usd: float
    error: str | None = None


@dataclass
class BenchmarkSummary:
    """Summary of a batch benchmark run."""

    total: int
    passed: int
    failed: int
    errors: int
    pass_rate: float
    results: list[BenchmarkResult] = field(default_factory=list)
    by_level: dict[str, dict[str, int]] = field(default_factory=dict)
    by_tag: dict[str, dict[str, int]] = field(default_factory=dict)


# Type for solver function: (target_url, description, config) -> solver_output_str
SolverFn = Callable[[str, str, dict[str, Any]], str]


class BenchmarkRunner:
    """Run XBOW challenges and collect results."""

    def __init__(self, platform: XBOWPlatform | None = None):
        self.platform = platform or XBOWPlatform()

    def run_single(
        self,
        challenge_id: str,
        solver_fn: SolverFn,
        config: dict[str, Any] | None = None,
    ) -> BenchmarkResult:
        """Run a single challenge through the full lifecycle."""
        config = config or {}
        info = self.platform.load_challenge(challenge_id)
        flag_expected = ""
        start_time = time.time()

        try:
            # Build with random flag
            flag_expected = self.platform.build_challenge(challenge_id)

            # Start challenge
            target_url = self.platform.start_challenge(challenge_id)

            # Re-read info in case start_challenge updated it (e.g., extra ports)
            active = getattr(self.platform, "_active", None)
            if active and challenge_id in active:
                info = active[challenge_id]

            # Run solver
            logger.info("Running solver on %s at %s", challenge_id, target_url)
            solver_output = solver_fn(target_url, info.description, config)

            # Verify flag
            success = self.platform.verify_flag(solver_output, flag_expected)
            elapsed = time.time() - start_time

            # Extract iteration/cost from config if solver provides them
            iterations = config.get("_iterations", 0)
            cost = config.get("_cost_usd", 0.0)

            return BenchmarkResult(
                challenge_id=challenge_id,
                name=info.name,
                level=info.level,
                tags=info.tags,
                success=success,
                flag_expected=flag_expected,
                flag_found=flag_expected if success else None,
                iterations=iterations,
                time_seconds=round(elapsed, 2),
                cost_usd=cost,
            )

        except Exception as e:
            elapsed = time.time() - start_time
            logger.error("Error running %s: %s", challenge_id, e)
            return BenchmarkResult(
                challenge_id=challenge_id,
                name=info.name,
                level=info.level,
                tags=info.tags,
                success=False,
                flag_expected=flag_expected,
                flag_found=None,
                iterations=0,
                time_seconds=round(elapsed, 2),
                cost_usd=0.0,
                error=str(e),
            )
        finally:
            try:
                self.platform.stop_challenge(challenge_id)
            except Exception as e:
                logger.warning("Failed to stop %s: %s", challenge_id, e)

    def run_batch(
        self,
        challenge_ids: list[str],
        solver_fn: SolverFn,
        config: dict[str, Any] | None = None,
    ) -> BenchmarkSummary:
        """Run multiple challenges sequentially."""
        results = []
        for i, cid in enumerate(challenge_ids, 1):
            logger.info("--- Challenge %d/%d: %s ---", i, len(challenge_ids), cid)
            result = self.run_single(cid, solver_fn, config)
            results.append(result)
            status = "PASS" if result.success else "FAIL"
            logger.info("%s: %s (%.1fs)", cid, status, result.time_seconds)

        return self._build_summary(results)

    def run_by_level(
        self,
        level: str | int,
        solver_fn: SolverFn,
        config: dict[str, Any] | None = None,
    ) -> BenchmarkSummary:
        """Run all challenges at a given level."""
        level_str = str(level)
        challenge_ids = [
            cid for cid in self.platform.list_challenges()
            if self.platform.load_challenge(cid).level == level_str
        ]
        logger.info("Found %d challenges at level %s", len(challenge_ids), level_str)
        return self.run_batch(challenge_ids, solver_fn, config)

    def run_by_tag(
        self,
        tag: str,
        solver_fn: SolverFn,
        config: dict[str, Any] | None = None,
    ) -> BenchmarkSummary:
        """Run all challenges with a given tag."""
        challenge_ids = [
            cid for cid in self.platform.list_challenges()
            if tag in self.platform.load_challenge(cid).tags
        ]
        logger.info("Found %d challenges with tag '%s'", len(challenge_ids), tag)
        return self.run_batch(challenge_ids, solver_fn, config)

    def _build_summary(self, results: list[BenchmarkResult]) -> BenchmarkSummary:
        """Build a summary from a list of results."""
        passed = sum(1 for r in results if r.success)
        errors = sum(1 for r in results if r.error)
        total = len(results)

        # By level
        by_level: dict[str, dict[str, int]] = {}
        for r in results:
            if r.level not in by_level:
                by_level[r.level] = {"total": 0, "passed": 0}
            by_level[r.level]["total"] += 1
            if r.success:
                by_level[r.level]["passed"] += 1

        # By tag
        tag_counter: dict[str, dict[str, int]] = {}
        for r in results:
            for tag in r.tags:
                if tag not in tag_counter:
                    tag_counter[tag] = {"total": 0, "passed": 0}
                tag_counter[tag]["total"] += 1
                if r.success:
                    tag_counter[tag]["passed"] += 1

        return BenchmarkSummary(
            total=total,
            passed=passed,
            failed=total - passed,
            errors=errors,
            pass_rate=round(passed / total * 100, 1) if total else 0.0,
            results=results,
            by_level=by_level,
            by_tag=tag_counter,
        )

    @staticmethod
    def save_results(summary: BenchmarkSummary, output_path: str | Path) -> None:
        """Save benchmark results to a JSON file."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "total": summary.total,
            "passed": summary.passed,
            "failed": summary.failed,
            "errors": summary.errors,
            "pass_rate": summary.pass_rate,
            "by_level": summary.by_level,
            "by_tag": summary.by_tag,
            "results": [asdict(r) for r in summary.results],
        }

        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        logger.info("Results saved to %s", path)

    @staticmethod
    def print_summary(summary: BenchmarkSummary) -> None:
        """Print a CLI-friendly summary table."""
        print(f"\n{'='*60}")
        print(f"Benchmark Results: {summary.passed}/{summary.total} passed ({summary.pass_rate}%)")
        print(f"{'='*60}")

        print(f"\n{'ID':<15} {'Level':>5} {'Status':<8} {'Time':>8} {'Error'}")
        print("-" * 60)
        for r in summary.results:
            status = "PASS" if r.success else "FAIL"
            error = (r.error[:30] + "...") if r.error and len(r.error) > 30 else (r.error or "")
            print(f"{r.challenge_id:<15} {r.level:>5} {status:<8} {r.time_seconds:>7.1f}s {error}")

        if summary.by_level:
            print("\nBy Level:")
            for level in sorted(summary.by_level, key=str):
                info = summary.by_level[level]
                rate = round(info["passed"] / info["total"] * 100, 1) if info["total"] else 0
                print(f"  Level {level}: {info['passed']}/{info['total']} ({rate}%)")

        if summary.by_tag:
            print("\nBy Tag:")
            for tag in sorted(summary.by_tag):
                info = summary.by_tag[tag]
                rate = round(info["passed"] / info["total"] * 100, 1) if info["total"] else 0
                print(f"  {tag}: {info['passed']}/{info['total']} ({rate}%)")
