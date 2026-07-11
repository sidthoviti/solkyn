#!/usr/bin/env python3
"""XBOW challenge inventory — parse all benchmark.json files and generate a summary."""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path


def load_benchmarks(benchmarks_dir: Path) -> list[dict]:
    """Load all benchmark.json files from the XBOW benchmarks directory."""
    challenges = []
    for challenge_dir in sorted(benchmarks_dir.iterdir()):
        if not challenge_dir.is_dir() or not challenge_dir.name.startswith("XBEN-"):
            continue

        benchmark_json = challenge_dir / "benchmark.json"
        if not benchmark_json.exists():
            print(f"  WARN: No benchmark.json in {challenge_dir.name}", file=sys.stderr)
            continue

        with open(benchmark_json) as f:
            data = json.load(f)

        # Count files in the challenge directory
        file_count = sum(1 for _ in challenge_dir.rglob("*") if _.is_file())

        challenges.append({
            "id": challenge_dir.name,
            "name": data.get("name", ""),
            "level": data.get("level", "?"),
            "tags": data.get("tags", []),
            "win_condition": data.get("win_condition", ""),
            "description": data.get("description", ""),
            "file_count": file_count,
        })

    return challenges


def print_table(challenges: list[dict]) -> None:
    """Print a formatted table of challenges."""
    print(f"{'ID':<15} {'Level':>5} {'Tags':<30} {'Name'}")
    print("-" * 90)
    for c in challenges:
        tags = ", ".join(c["tags"])
        print(f"{c['id']:<15} {c['level']:>5} {tags:<30} {c['name']}")


def print_summary(challenges: list[dict]) -> None:
    """Print level and tag counts."""
    level_counts = Counter(c["level"] for c in challenges)
    tag_counts = Counter(tag for c in challenges for tag in c["tags"])

    print(f"\nTotal challenges: {len(challenges)}")
    print("\nBy level:")
    for level in sorted(level_counts, key=str):
        print(f"  Level {level}: {level_counts[level]}")

    print("\nBy tag:")
    for tag, count in tag_counts.most_common():
        print(f"  {tag}: {count}")


def main() -> None:
    benchmarks_dir = Path("benchmarks/xbow/benchmarks")
    if not benchmarks_dir.exists():
        print(f"Error: {benchmarks_dir} not found. Clone XBOW repo first.", file=sys.stderr)
        sys.exit(1)

    challenges = load_benchmarks(benchmarks_dir)
    print_table(challenges)
    print_summary(challenges)

    # Write JSON inventory
    output_path = Path("docs/xbow-challenge-inventory.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(challenges, f, indent=2)
    print(f"\nJSON inventory written to {output_path}")


if __name__ == "__main__":
    main()
