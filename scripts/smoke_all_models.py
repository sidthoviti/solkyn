#!/usr/bin/env python3
"""Smoke-test all release/v1 models on a single L1 challenge.

Validates BEFORE any production sweep:
- The OpenRouter slug actually resolves (no 404).
- Tool-calling works (model issued >=1 tool call within the iter cap).
- All metrics we plan to publish are captured non-null in stats.json.
- Per-call upstream cost is recorded by OpenRouter (where applicable).
- Reproducibility metadata (git SHA, kali image digest, effective
  LLM params, seed, seed_supported) lands in config.json.
- Anthropic prompt-cache marker round-trips (Opus only:
  iter 1 should populate cache_creation_input_tokens, iter 2+
  should populate cache_read_input_tokens).

Writes a green/red checklist per model to results/smoke.md.
Per user direction: 'Smoke test should also capture all metrics
we discussed'.

The smoke runs every model SEQUENTIALLY (no parallel) so the user
can confirm OSS slugs / pricing / behaviour interactively before
the production sweep launches.

Default smoke challenge: XBEN-058-24 — consistent L1 IDOR pass in
prior sweeps, fast (~25s on gpt-5.4 at 5 iters).

Usage
-----

    # Smoke all 6 models
    python scripts/smoke_all_models.py

    # Smoke a single model
    python scripts/smoke_all_models.py --model azure-gpt54

    # Different challenge / iter cap
    python scripts/smoke_all_models.py --challenge XBEN-073-24 --max-iterations 8
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

logger = logging.getLogger("solkyn.smoke")

# Pre-registered model roster (matches docs/methodology.md §2).
DEFAULT_MODELS = [
    "azure-gpt54",
    "openrouter-opus47",
    "openrouter-gemini3pro",
    "openrouter-glm51",
    "openrouter-kimi26",
    "openrouter-deepseek-r4",
]

DEFAULT_CHALLENGE = "XBEN-058-24"
DEFAULT_ITERS = 5


# ---------------------------------------------------------------------------
# Metric checks
# ---------------------------------------------------------------------------

def _required_stats_fields() -> list[str]:
    return [
        "success",
        "exit_reason",
        "iterations",
        "duration_seconds",
        "tool_calls",
        "input_tokens",
        "output_tokens",
        "cache_read_input_tokens",
        "cache_creation_input_tokens",
        "cost_usd",
        "refusal_count",
        "error",
    ]


def _required_config_fields() -> list[str]:
    return [
        "challenge_id",
        "name",
        "level",
        "tags",
        "target_url",
        "model",
        "provider",
        "solver",
        "mode",
        "max_iterations",
        "expected_flag",
        "git_sha",
        "kali_image_digest",
        "effective_llm_params",
    ]


def _is_openrouter_model(provider_key: str) -> bool:
    return provider_key.startswith("openrouter-")


def _is_anthropic_model(provider_key: str, config_json: dict) -> bool:
    if "claude" in (config_json.get("model") or "").lower():
        return True
    if "opus" in provider_key or "sonnet" in provider_key:
        return True
    return False


def check_smoke_result(
    provider_key: str,
    attempt_dir: Path | None,
    subprocess_rc: int,
) -> dict:
    """Run all smoke validations against an attempt dir. Returns a
    dict mapping each check name to True/False plus a string note.
    """
    checks: dict[str, tuple[bool, str]] = {}

    def add(name: str, ok: bool, note: str = "") -> None:
        checks[name] = (ok, note)

    add("subprocess_succeeded", subprocess_rc == 0,
        f"run_challenges.py exit code {subprocess_rc}")

    if attempt_dir is None or not attempt_dir.exists():
        add("attempt_dir_created", False, "no attempt dir produced")
        return _flatten(checks)
    add("attempt_dir_created", True, str(attempt_dir))

    stats_path = attempt_dir / "stats.json"
    config_path = attempt_dir / "config.json"
    events_path = attempt_dir / "logs" / "events.jsonl"

    # stats.json exists + parses
    if not stats_path.exists():
        add("stats_json_exists", False, "missing")
        return _flatten(checks)
    add("stats_json_exists", True)
    try:
        stats = json.loads(stats_path.read_text())
    except json.JSONDecodeError as e:
        add("stats_json_parses", False, str(e))
        return _flatten(checks)
    add("stats_json_parses", True)

    # config.json exists + parses
    config = {}
    if config_path.exists():
        add("config_json_exists", True)
        try:
            config = json.loads(config_path.read_text())
            add("config_json_parses", True)
        except json.JSONDecodeError as e:
            add("config_json_parses", False, str(e))
    else:
        add("config_json_exists", False, "missing")

    # Per-field presence in stats
    for field in _required_stats_fields():
        present = field in stats
        add(f"stats.{field}_present", present,
            "" if present else "missing")

    # Per-field presence in config
    for field in _required_config_fields():
        present = field in config
        add(f"config.{field}_present", present,
            "" if present else "missing")

    # Tool calls > 0 (model actually issued tool calls)
    tool_calls = stats.get("tool_calls", 0) or 0
    add("tool_calls_gt_0", tool_calls > 0,
        f"tool_calls={tool_calls} (model issued tool calls)")

    # Token capture
    in_tok = stats.get("input_tokens", 0) or 0
    out_tok = stats.get("output_tokens", 0) or 0
    add("input_tokens_gt_0", in_tok > 0, f"input_tokens={in_tok}")
    add("output_tokens_gt_0", out_tok > 0, f"output_tokens={out_tok}")

    # Cost local always present + > 0
    cost = stats.get("cost_usd")
    add("cost_usd_positive", cost is not None and cost > 0,
        f"cost_usd={cost}")

    # Upstream cost (OpenRouter only)
    if _is_openrouter_model(provider_key):
        upstream = stats.get("upstream_cost_usd")
        add("upstream_cost_captured", upstream is not None,
            f"upstream_cost_usd={upstream} (OpenRouter ground truth)")
        if upstream is not None and cost is not None and upstream > 0:
            delta = abs(cost - upstream) / upstream * 100
            # Reconciliation is INFORMATIONAL ONLY, not a hard check.
            # OpenRouter's usage.cost is the ground truth and is what
            # we publish. Local cost (from our priced per-1k table)
            # is best-effort: it can be 2-4x off on reasoning models
            # (verified live with DeepSeek V4 Pro: 36k visible tokens
            # but 3.4x billed — they price tool-orchestration / hidden
            # reasoning tokens not surfaced in usage.prompt/completion).
            # We always log delta so the report shows it, but failing
            # the smoke on delta would block models that work fine.
            add("cost_reconciliation_logged", True,
                f"delta {delta:.1f}% (informational; upstream is ground truth)")
    else:
        # Native Azure: no upstream_cost_usd by design.
        add("upstream_cost_captured", True,
            "skipped (native provider does not surface usage.cost)")

    # exit_reason valid
    valid_reasons = {
        "flag_found", "max_iterations", "no_tool_calls",
        "time_limit", "cost_limit", "error",
    }
    er = stats.get("exit_reason")
    add("exit_reason_valid", er in valid_reasons,
        f"exit_reason={er}")

    # Anthropic cache marker round-trip
    if _is_anthropic_model(provider_key, config):
        cache_creation = stats.get("cache_creation_input_tokens", 0) or 0
        cache_read = stats.get("cache_read_input_tokens", 0) or 0
        iters = stats.get("iterations", 0) or 0
        # Cache only activates on iter 2+ (first iter writes, subsequent
        # iters read). When the model solves in 1 iter — which is a
        # GOOD outcome — there is no opportunity for the cache to be
        # observed. Also: Bedrock and Google routes don't honor the
        # Anthropic OpenAI-compat cache_control marker; only the
        # Anthropic-direct route does. Skip the check in either case.
        routed_via_anthropic_direct = "anthropic" in str(
            (config.get("effective_llm_params") or {})
            .get("extra_body", {})
            .get("provider", {})
            .get("order", [])
        ).lower()
        if iters >= 2 and routed_via_anthropic_direct:
            add("anthropic_cache_active",
                (cache_creation > 0) or (cache_read > 0),
                f"cache_creation={cache_creation} cache_read={cache_read}")
        else:
            add("anthropic_cache_active", True,
                f"skipped (iters={iters}, direct={routed_via_anthropic_direct}; "
                "cache only observable on iter 2+ via Anthropic-direct route)")

    # events.jsonl exists + has llm_call events
    if events_path.exists():
        add("events_jsonl_exists", True)
        try:
            lines = [
                json.loads(line)
                for line in events_path.read_text().splitlines()
                if line.strip()
            ]
            # EventLogger writes the discriminator under the key 'type'
            # (not 'event' — verified in scans/smoke_v1).
            llm_calls = [e for e in lines if e.get("type") == "llm_call"]
            add("events_jsonl_parses", True,
                f"{len(lines)} events, {len(llm_calls)} llm_call events")
            add("llm_call_events_present", len(llm_calls) > 0,
                f"llm_call event count = {len(llm_calls)}")
            # Per-call upstream cost (OpenRouter only)
            if _is_openrouter_model(provider_key) and llm_calls:
                with_upstream = sum(
                    1 for e in llm_calls
                    if e.get("upstream_cost_usd") is not None
                )
                add("per_call_upstream_cost",
                    with_upstream > 0,
                    f"{with_upstream}/{len(llm_calls)} llm_call events "
                    "have upstream_cost_usd")
        except json.JSONDecodeError as e:
            add("events_jsonl_parses", False, str(e))
    else:
        add("events_jsonl_exists", False, "missing")

    return _flatten(checks)


def _flatten(checks: dict[str, tuple[bool, str]]) -> dict:
    return {
        "passed": all(ok for ok, _ in checks.values()),
        "checks": [
            {"name": name, "ok": ok, "note": note}
            for name, (ok, note) in checks.items()
        ],
    }


# ---------------------------------------------------------------------------
# Smoke runner
# ---------------------------------------------------------------------------


def _newest_attempt_dir(challenge_id: str, output_root: Path) -> Path | None:
    challenge_dir = output_root / challenge_id
    if not challenge_dir.exists():
        return None
    attempts = sorted(
        p for p in challenge_dir.iterdir()
        if p.is_dir() and "attempt_" in p.name and (p / "stats.json").exists()
    )
    return attempts[-1] if attempts else None


def smoke_one_model(
    provider_key: str,
    *,
    challenge_id: str,
    max_iterations: int,
    config_path: Path,
    smoke_output: Path,
) -> dict:
    """Run one model on one challenge; return {provider, result, validations}."""
    logger.info("=" * 70)
    logger.info("SMOKE %s on %s (max_iter=%d)", provider_key, challenge_id, max_iterations)
    logger.info("=" * 70)

    cmd: list[str] = [
        sys.executable,
        str(PROJECT_ROOT / "scripts/run_challenges.py"),
        "-c", challenge_id,
        "--config", str(config_path),
        "--provider", provider_key,
        "--mode", "whitebox",
        "--solver", "single_loop_compact",
        "--max-iterations", str(max_iterations),
        "--attempts", "1",
        "--no-generate-progress",
        "--output", str(smoke_output),
    ]

    started = time.time()
    proc = subprocess.run(cmd, capture_output=False, text=True)
    elapsed = time.time() - started

    attempt_dir = _newest_attempt_dir(challenge_id, smoke_output)
    validations = check_smoke_result(provider_key, attempt_dir, proc.returncode)

    return {
        "provider": provider_key,
        "challenge": challenge_id,
        "attempt_dir": str(attempt_dir) if attempt_dir else None,
        "subprocess_rc": proc.returncode,
        "wall_seconds": round(elapsed, 2),
        "validations": validations,
    }


def write_smoke_report(
    results: list[dict], report_path: Path,
) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    lines.append("# Smoke test report — release/v1\n")
    lines.append(
        f"_Generated: {time.strftime('%Y-%m-%d %H:%M:%S %Z', time.gmtime())}_\n"
    )
    lines.append("")

    # Header table
    lines.append("## Summary\n")
    lines.append(
        "| Provider | Passed all checks | Wall (s) | Attempt dir |"
    )
    lines.append("|---|---|---:|---|")
    for r in results:
        ok = "✅" if r["validations"]["passed"] else "❌"
        lines.append(
            f"| `{r['provider']}` | {ok} | {r['wall_seconds']} | "
            f"`{r['attempt_dir'] or '(none)'}` |"
        )
    lines.append("")

    # Per-model detail
    for r in results:
        lines.append(f"## `{r['provider']}`")
        lines.append("")
        lines.append(
            f"- Challenge: `{r['challenge']}`  ·  subprocess rc: {r['subprocess_rc']}"
            f"  ·  wall: {r['wall_seconds']}s"
        )
        lines.append("")
        lines.append("| Check | Result | Note |")
        lines.append("|---|---|---|")
        for c in r["validations"]["checks"]:
            mark = "✅" if c["ok"] else "❌"
            note = c.get("note", "").replace("\n", " ").replace("|", "\\|")
            lines.append(f"| `{c['name']}` | {mark} | {note} |")
        lines.append("")

    report_path.write_text("\n".join(lines))
    logger.info("Wrote smoke report to %s", report_path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke-test release/v1 models")
    parser.add_argument(
        "--model", action="append",
        help="Provider key (repeatable). Default: all 6 release/v1 models.",
    )
    parser.add_argument(
        "--challenge", default=DEFAULT_CHALLENGE,
        help=f"Challenge ID (default {DEFAULT_CHALLENGE}: L1 IDOR, consistent pass)",
    )
    parser.add_argument(
        "--max-iterations", type=int, default=DEFAULT_ITERS,
        help=f"Iter cap per model (default {DEFAULT_ITERS})",
    )
    parser.add_argument(
        "--config", default="configs/default.yaml",
        help="YAML config path",
    )
    parser.add_argument(
        "--output", default="scans/smoke_v1",
        help="Output dir for smoke runs (kept separate from production sweep)",
    )
    parser.add_argument(
        "--report", default="results/smoke.md",
        help="Report markdown path (default results/smoke.md)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)-22s %(levelname)-5s %(message)s",
        datefmt="%H:%M:%S",
    )

    if not shutil.which("docker"):
        logger.error("docker required — smoke runs the full Kali container path")
        return 2

    config_path = PROJECT_ROOT / args.config
    if not config_path.exists():
        logger.error("Config not found: %s", config_path)
        return 2

    models = args.model or DEFAULT_MODELS
    smoke_output = PROJECT_ROOT / args.output
    smoke_output.mkdir(parents=True, exist_ok=True)
    logger.info("Smoke-testing %d model(s): %s", len(models), models)

    results: list[dict] = []
    for provider_key in models:
        r = smoke_one_model(
            provider_key,
            challenge_id=args.challenge,
            max_iterations=args.max_iterations,
            config_path=config_path,
            smoke_output=smoke_output,
        )
        results.append(r)

        # Live summary
        ok = "✅" if r["validations"]["passed"] else "❌"
        failed_checks = [
            c["name"] for c in r["validations"]["checks"] if not c["ok"]
        ]
        logger.info(
            "%s %s: %s  failed: %s",
            ok, provider_key,
            "PASS ALL CHECKS" if not failed_checks else "FAIL",
            failed_checks[:3] if failed_checks else "(none)",
        )

    write_smoke_report(results, PROJECT_ROOT / args.report)

    # Exit code = 0 iff all models passed all checks
    all_passed = all(r["validations"]["passed"] for r in results)
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
