#!/usr/bin/env python3
"""Aggregate release/v1 sweep results into publishable tables.

Reads every attempt under `scans/full_sweep_v1/{model-leg}/{XBEN-id}/`
and produces:

  results/per_attempt.csv          — long-format: one row per attempt
  results/leaderboard.md           — pass@1 / pass@3 + bootstrap CIs per model
  results/per_level.md             — pass@1/pass@3 broken out by L1/L2/L3
  results/per_vuln_class.md        — pass@1/pass@3 by primary tag
  results/cross_model_union.md     — challenges solved by ANY model (per-model attribution)
  results/passN_delta.md           — pass@3 − pass@1 per model (does retry help?)
  results/cost_summary.md          — total spend per model (local + upstream where known)

All tables also written to `results/aggregate.json` for downstream tools.

Stats source: stats.json in each attempt directory (T34b/T34c schema).
Inventory: docs/xbow-challenge-inventory.json (level, tags).

pass@k computed unbiased (Chen & Kalmus 2021) when n >= k attempts available:
    pass@k = 1 - C(n-c, k) / C(n, k)
where c = number of successful attempts out of n.

CIs: percentile bootstrap, B = 1000 resamples over challenges (not attempts),
two-sided 95%.

Usage
-----

    python scripts/aggregate_results.py
    python scripts/aggregate_results.py --sweep-root scans/full_sweep_v1
    python scripts/aggregate_results.py --output results/
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import math
import random
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

logger = logging.getLogger("solkyn.aggregate")


# ---------------------------------------------------------------------------
# pass@k math
# ---------------------------------------------------------------------------


def passk_unbiased(n: int, c: int, k: int) -> float:
    """Unbiased pass@k estimator (Chen et al. 2021).

    n: total attempts, c: successes, k: target.
    Returns 1.0 if c == n; 0.0 if c == 0 and n >= k; otherwise the
    standard combinatorial estimator.
    """
    if n - c < k:
        return 1.0
    return 1.0 - math.comb(n - c, k) / math.comb(n, k)


def bootstrap_ci(
    values: list[float], *, alpha: float = 0.05, b: int = 1000, seed: int = 0,
) -> tuple[float, float]:
    """Percentile bootstrap CI for the mean of `values`."""
    if not values:
        return (0.0, 0.0)
    rng = random.Random(seed)
    n = len(values)
    means = []
    for _ in range(b):
        sample = [values[rng.randrange(n)] for _ in range(n)]
        means.append(sum(sample) / n)
    means.sort()
    lo = means[int(alpha / 2 * b)]
    hi = means[int((1 - alpha / 2) * b) - 1]
    return (lo, hi)


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def load_inventory(path: Path) -> dict[str, dict]:
    if not path.exists():
        logger.warning("Inventory missing at %s; level/tags will be empty", path)
        return {}
    data = json.loads(path.read_text())
    return {item["id"]: item for item in data}


def _parse_model_leg(dirname: str) -> tuple[str, str]:
    """`openrouter-opus47-whitebox` → ('openrouter-opus47', 'whitebox')."""
    for leg in ("whitebox", "blackbox"):
        suffix = f"-{leg}"
        if dirname.endswith(suffix):
            return dirname[: -len(suffix)], leg
    return dirname, "unknown"


def load_attempts(sweep_root: Path) -> list[dict[str, Any]]:
    """Walk sweep_root/{model-leg}/{XBEN-id}/{attempt_dir}/stats.json."""
    rows: list[dict[str, Any]] = []
    if not sweep_root.exists():
        logger.warning("Sweep root not found: %s", sweep_root)
        return rows

    for model_leg_dir in sorted(sweep_root.iterdir()):
        if not model_leg_dir.is_dir():
            continue
        model, leg = _parse_model_leg(model_leg_dir.name)

        for challenge_dir in sorted(model_leg_dir.iterdir()):
            if not challenge_dir.is_dir() or not challenge_dir.name.startswith("XBEN"):
                continue
            challenge_id = challenge_dir.name

            attempt_idx = 0
            for attempt_dir in sorted(challenge_dir.iterdir()):
                stats_path = attempt_dir / "stats.json"
                if not stats_path.exists():
                    continue
                try:
                    stats = json.loads(stats_path.read_text())
                except json.JSONDecodeError:
                    logger.warning("Bad stats.json: %s", stats_path)
                    continue
                attempt_idx += 1
                rows.append({
                    "model": model,
                    "leg": leg,
                    "challenge_id": challenge_id,
                    "attempt": attempt_idx,
                    "attempt_dir": str(attempt_dir),
                    "success": bool(stats.get("success", False)),
                    "exit_reason": stats.get("exit_reason"),
                    "iterations": stats.get("iterations"),
                    "duration_seconds": stats.get("duration_seconds"),
                    "tool_calls": stats.get("tool_calls"),
                    "input_tokens": stats.get("input_tokens"),
                    "output_tokens": stats.get("output_tokens"),
                    "cache_read_input_tokens": stats.get("cache_read_input_tokens"),
                    "cache_creation_input_tokens": stats.get("cache_creation_input_tokens"),
                    "cost_usd": stats.get("cost_usd"),
                    "upstream_cost_usd": stats.get("upstream_cost_usd"),
                    "refusal_count": stats.get("refusal_count"),
                    "error": stats.get("error"),
                })
    return rows


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


def _group_by_challenge(
    rows: list[dict],
) -> dict[tuple[str, str, str], list[dict]]:
    """Group attempts by (model, leg, challenge_id)."""
    grouped: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for r in rows:
        grouped[(r["model"], r["leg"], r["challenge_id"])].append(r)
    return grouped


def compute_passk_per_model(
    rows: list[dict], *, k_values: tuple[int, ...] = (1, 3),
) -> dict[tuple[str, str], dict]:
    """Compute pass@k per (model, leg).

    For each challenge under that model+leg, count successes/attempts,
    compute per-challenge pass@k (unbiased), then average across challenges.
    """
    grouped = _group_by_challenge(rows)
    by_model: dict[tuple[str, str], dict] = defaultdict(
        lambda: {"per_challenge": {}, "passk": {}}
    )

    # per challenge: list of (n, c)
    for (model, leg, cid), attempts in grouped.items():
        n = len(attempts)
        c = sum(1 for a in attempts if a["success"])
        by_model[(model, leg)]["per_challenge"][cid] = {
            "n": n, "c": c, "any_success": c > 0,
        }

    for key, info in by_model.items():
        for k in k_values:
            per_chal_passk = []
            for cid, stat in info["per_challenge"].items():
                if stat["n"] >= k:
                    per_chal_passk.append(passk_unbiased(stat["n"], stat["c"], k))
                elif k == 1:
                    per_chal_passk.append(1.0 if stat["c"] > 0 else 0.0)
                # else: skip challenges with too few attempts for pass@k
            mean = sum(per_chal_passk) / len(per_chal_passk) if per_chal_passk else 0.0
            lo, hi = bootstrap_ci(per_chal_passk)
            info["passk"][f"pass@{k}"] = {
                "mean": mean, "ci_low": lo, "ci_high": hi,
                "n_challenges": len(per_chal_passk),
            }

    return dict(by_model)


def compute_per_level(
    rows: list[dict], inventory: dict[str, dict], *, k_values=(1, 3),
) -> dict:
    """{model_leg: {level: {pass@k: ...}}}."""
    grouped = _group_by_challenge(rows)
    out: dict = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    for (model, leg, cid), attempts in grouped.items():
        level = (inventory.get(cid) or {}).get("level", "?")
        n = len(attempts)
        c = sum(1 for a in attempts if a["success"])
        for k in k_values:
            if n >= k:
                out[(model, leg)][level][f"pass@{k}"].append(
                    passk_unbiased(n, c, k))
    # Reduce
    final: dict = {}
    for key, level_map in out.items():
        final[key] = {}
        for level, kmap in level_map.items():
            final[key][level] = {
                kname: {
                    "mean": sum(vals) / len(vals) if vals else 0.0,
                    "n": len(vals),
                }
                for kname, vals in kmap.items()
            }
    return final


def compute_per_vuln_class(
    rows: list[dict], inventory: dict[str, dict], *, k_values=(1, 3),
) -> dict:
    grouped = _group_by_challenge(rows)
    out: dict = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    for (model, leg, cid), attempts in grouped.items():
        tags = (inventory.get(cid) or {}).get("tags", []) or ["untagged"]
        primary = tags[0]
        n = len(attempts)
        c = sum(1 for a in attempts if a["success"])
        for k in k_values:
            if n >= k:
                out[(model, leg)][primary][f"pass@{k}"].append(
                    passk_unbiased(n, c, k))
    final: dict = {}
    for key, tag_map in out.items():
        final[key] = {}
        for tag, kmap in tag_map.items():
            final[key][tag] = {
                kname: {
                    "mean": sum(vals) / len(vals) if vals else 0.0,
                    "n": len(vals),
                }
                for kname, vals in kmap.items()
            }
    return final


def compute_cross_model_union(rows: list[dict]) -> dict:
    """Whitebox only: which challenges did ANY model solve in any attempt?"""
    wb = [r for r in rows if r["leg"] == "whitebox"]
    solved_by: dict[str, set[str]] = defaultdict(set)
    all_challenges: set[str] = set()
    for r in wb:
        all_challenges.add(r["challenge_id"])
        if r["success"]:
            solved_by[r["challenge_id"]].add(r["model"])
    union_solved = {cid for cid, models in solved_by.items() if models}
    per_model_solo: dict[str, set[str]] = defaultdict(set)
    for cid, models in solved_by.items():
        if len(models) == 1:
            (only,) = models
            per_model_solo[only].add(cid)
    return {
        "total_challenges": len(all_challenges),
        "union_solved": len(union_solved),
        "union_solved_ids": sorted(union_solved),
        "per_model_solo_solves": {
            m: sorted(cids) for m, cids in per_model_solo.items()
        },
        "per_challenge_solvers": {
            cid: sorted(models) for cid, models in solved_by.items()
        },
    }


def compute_cost_summary(rows: list[dict]) -> dict:
    by_model: dict[tuple[str, str], dict] = defaultdict(
        lambda: {
            "n_attempts": 0,
            "cost_usd_local": 0.0,
            "upstream_cost_usd": 0.0,
            "upstream_attempts": 0,
        }
    )
    for r in rows:
        key = (r["model"], r["leg"])
        by_model[key]["n_attempts"] += 1
        by_model[key]["cost_usd_local"] += r.get("cost_usd") or 0.0
        if r.get("upstream_cost_usd") is not None:
            by_model[key]["upstream_cost_usd"] += r["upstream_cost_usd"]
            by_model[key]["upstream_attempts"] += 1
    return {f"{m}-{leg}": v for (m, leg), v in by_model.items()}


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


def _fmt_pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def render_leaderboard(passk: dict) -> str:
    lines = ["# Leaderboard — release/v1 XBOW sweep\n"]
    lines.append(
        "| Model | Leg | n challenges | pass@1 (95% CI) | pass@3 (95% CI) |"
    )
    lines.append("|---|---|---:|---|---|")
    rows = []
    for (model, leg), info in passk.items():
        p1 = info["passk"].get("pass@1", {})
        p3 = info["passk"].get("pass@3", {})
        rows.append((p1.get("mean", 0), model, leg, p1, p3))
    rows.sort(key=lambda x: -x[0])
    for _, model, leg, p1, p3 in rows:
        lines.append(
            f"| `{model}` | {leg} | {p1.get('n_challenges', 0)} | "
            f"{_fmt_pct(p1.get('mean', 0))} "
            f"[{_fmt_pct(p1.get('ci_low', 0))}, {_fmt_pct(p1.get('ci_high', 0))}] | "
            f"{_fmt_pct(p3.get('mean', 0))} "
            f"[{_fmt_pct(p3.get('ci_low', 0))}, {_fmt_pct(p3.get('ci_high', 0))}] |"
        )
    lines.append("\n_CIs are percentile bootstrap over challenges, B=1000. "
                 "pass@k uses unbiased estimator (Chen et al. 2021)._\n")
    return "\n".join(lines)


def render_per_level(per_level: dict) -> str:
    lines = ["# pass@k by level — release/v1\n"]
    for (model, leg), level_map in sorted(per_level.items()):
        lines.append(f"## `{model}` ({leg})\n")
        lines.append("| Level | n | pass@1 | pass@3 |")
        lines.append("|---|---:|---|---|")
        for level in sorted(level_map.keys()):
            kmap = level_map[level]
            p1 = kmap.get("pass@1", {})
            p3 = kmap.get("pass@3", {})
            lines.append(
                f"| L{level} | {p1.get('n', 0)} | "
                f"{_fmt_pct(p1.get('mean', 0))} | "
                f"{_fmt_pct(p3.get('mean', 0))} |"
            )
        lines.append("")
    return "\n".join(lines)


def render_per_vuln_class(per_vuln: dict) -> str:
    lines = ["# pass@k by vulnerability class — release/v1\n"]
    for (model, leg), tag_map in sorted(per_vuln.items()):
        lines.append(f"## `{model}` ({leg})\n")
        lines.append("| Class | n | pass@1 | pass@3 |")
        lines.append("|---|---:|---|---|")
        # sort by pass@1 desc
        ranked = sorted(
            tag_map.items(),
            key=lambda kv: -kv[1].get("pass@1", {}).get("mean", 0),
        )
        for tag, kmap in ranked:
            p1 = kmap.get("pass@1", {})
            p3 = kmap.get("pass@3", {})
            lines.append(
                f"| `{tag}` | {p1.get('n', 0)} | "
                f"{_fmt_pct(p1.get('mean', 0))} | "
                f"{_fmt_pct(p3.get('mean', 0))} |"
            )
        lines.append("")
    return "\n".join(lines)


def render_cross_model_union(union: dict) -> str:
    lines = ["# Cross-model union — release/v1 (whitebox)\n"]
    lines.append(
        f"- Challenges seen: **{union['total_challenges']}**"
    )
    lines.append(
        f"- Union solve (any model, any attempt): **{union['union_solved']}** "
        f"({_fmt_pct(union['union_solved'] / max(union['total_challenges'], 1))})"
    )
    lines.append("\n## Per-model solo solves (only this model got it)\n")
    lines.append("| Model | Solo solves |")
    lines.append("|---|---:|")
    for model, cids in sorted(
        union["per_model_solo_solves"].items(),
        key=lambda kv: -len(kv[1]),
    ):
        lines.append(f"| `{model}` | {len(cids)} |")
    return "\n".join(lines)


def render_passN_delta(passk: dict) -> str:
    lines = ["# pass@3 − pass@1 (does retry help?) — release/v1\n"]
    lines.append("| Model | Leg | pass@1 | pass@3 | Δ |")
    lines.append("|---|---|---|---|---|")
    rows = []
    for (model, leg), info in passk.items():
        p1 = info["passk"].get("pass@1", {}).get("mean", 0.0)
        p3 = info["passk"].get("pass@3", {}).get("mean", 0.0)
        rows.append((p3 - p1, model, leg, p1, p3))
    rows.sort(key=lambda x: -x[0])
    for delta, model, leg, p1, p3 in rows:
        lines.append(
            f"| `{model}` | {leg} | {_fmt_pct(p1)} | {_fmt_pct(p3)} | "
            f"{'+' if delta >= 0 else ''}{_fmt_pct(delta)} |"
        )
    return "\n".join(lines)


def render_cost_summary(cost: dict) -> str:
    lines = ["# Cost summary — release/v1\n"]
    lines.append(
        "| Model-leg | Attempts | Local $ (priced) | "
        "Upstream $ (OpenRouter ground truth) | Upstream coverage |"
    )
    lines.append("|---|---:|---:|---:|---:|")
    total_local = 0.0
    total_upstream = 0.0
    for key in sorted(cost.keys()):
        v = cost[key]
        local = v["cost_usd_local"]
        upstream = v["upstream_cost_usd"]
        total_local += local
        total_upstream += upstream
        upstream_cov = (
            f"{v['upstream_attempts']}/{v['n_attempts']}"
            if v["n_attempts"] else "0/0"
        )
        lines.append(
            f"| `{key}` | {v['n_attempts']} | ${local:.2f} | ${upstream:.2f} | {upstream_cov} |"
        )
    lines.append(f"| **Total** | | **${total_local:.2f}** | **${total_upstream:.2f}** | |")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def write_per_attempt_csv(rows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("")
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate v1 sweep results")
    parser.add_argument(
        "--sweep-root", default="scans/full_sweep_v1",
        help="Root containing {model-leg}/{XBEN-id}/attempts (default: scans/full_sweep_v1)",
    )
    parser.add_argument(
        "--inventory", default="docs/xbow-challenge-inventory.json",
        help="XBOW challenge inventory JSON",
    )
    parser.add_argument(
        "--output", default="results",
        help="Output directory for CSV + markdown reports",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)-22s %(levelname)-5s %(message)s",
        datefmt="%H:%M:%S",
    )

    sweep_root = PROJECT_ROOT / args.sweep_root
    output = PROJECT_ROOT / args.output
    output.mkdir(parents=True, exist_ok=True)
    inventory = load_inventory(PROJECT_ROOT / args.inventory)

    rows = load_attempts(sweep_root)
    logger.info("Loaded %d attempts from %s", len(rows), sweep_root)
    if not rows:
        logger.warning("No attempts found — nothing to aggregate")
        return 1

    passk = compute_passk_per_model(rows)
    per_level = compute_per_level(rows, inventory)
    per_vuln = compute_per_vuln_class(rows, inventory)
    union = compute_cross_model_union(rows)
    cost = compute_cost_summary(rows)

    write_per_attempt_csv(rows, output / "per_attempt.csv")
    (output / "leaderboard.md").write_text(render_leaderboard(passk))
    (output / "per_level.md").write_text(render_per_level(per_level))
    (output / "per_vuln_class.md").write_text(render_per_vuln_class(per_vuln))
    (output / "cross_model_union.md").write_text(render_cross_model_union(union))
    (output / "passN_delta.md").write_text(render_passN_delta(passk))
    (output / "cost_summary.md").write_text(render_cost_summary(cost))

    # Combined JSON for downstream / blog
    json_dump = {
        "passk_per_model": {
            f"{m}-{leg}": v for (m, leg), v in passk.items()
        },
        "per_level": {
            f"{m}-{leg}": v for (m, leg), v in per_level.items()
        },
        "per_vuln_class": {
            f"{m}-{leg}": v for (m, leg), v in per_vuln.items()
        },
        "cross_model_union": union,
        "cost_summary": cost,
    }
    (output / "aggregate.json").write_text(json.dumps(json_dump, indent=2))

    logger.info("Wrote: %s/{per_attempt.csv,leaderboard.md,per_level.md,"
                "per_vuln_class.md,cross_model_union.md,passN_delta.md,"
                "cost_summary.md,aggregate.json}", output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
