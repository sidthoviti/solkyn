# Solver Selection — Existing-Data Analysis

> **Date**: 2026-05-21
> **Inputs**: `scans/sweeps/{baseline-1777555993,hacksynth-1777481062,xbow_wins-1777466103}.json`
> **Decision**: `single_loop_compact` (xbow_wins sweep)

## Summary table — pass@1 across 104 challenges

| Sweep alias | Solver (best inference) | Mode | Pass@1 | L1 | L2 | L3 |
|---|---|---|---|---|---|---|
| `baseline` | `single_loop` | white-box | 90/104 = 86.5% | 42/45 | 43/51 | 5/8 |
| `hacksynth` | `hacksynth` | white-box | 89/104 = 85.6% | 41/45 | 42/51 | 6/8 |
| **`xbow_wins`** | **`single_loop_compact`** | white-box | **93/104 = 89.4%** | **43/45** | **45/51** | 5/8 |

All three sweeps were run on `azure-gpt54` at `--max-iterations 25` and represent honest, post-S30 (playbook scrub) and post-S32 (placeholder-flag fix) data.

## Why `single_loop_compact` wins

- **Highest pass@1** (+3 over `baseline`, +4 over `hacksynth`)
- **Strictly dominates on L1 + L2** — the bulk of the benchmark
- **Loses by 1 on L3** vs `hacksynth` (5/8 vs 6/8) — `hacksynth`'s rolling working memory may help the longest contexts, but the L3 set is too small (n=8) for that delta to be statistically meaningful.

Mean per-solve cost numbers (≈$41 / $30 / $39) are NOT cited as a tiebreaker — these come from pre-S33 placeholder pricing and have a known calibration error (see [docs/development-log.md](../docs/development-log.md) S33). Cost comparison would need a re-run on calibrated pricing, which we are not doing for v1.

## Selected configuration for the v1 sweep

```bash
python scripts/run_challenges.py \
    -c <CID> \
    --provider <provider> \
    --mode whitebox \
    --solver single_loop_compact \
    --max-iterations 25 \
    --max-iterations-l3 50 \
    --attempts 1 \
    --no-generate-progress
```

Three independent invocations per (model, challenge) for `n=3` pass@k variance — driven by `scripts/run_full_sweep.py`.

## Solver A/B trade-offs (for the public writeup, no re-runs needed)

| Solver | Strength | Weakness |
|---|---|---|
| `single_loop` | Simplest (transparent reasoning trace, easiest to debug, easiest to reproduce externally). | Long-tail challenges hit the model context limit; iteration efficiency drops late in long runs. |
| `single_loop_compact` | Adds context-window-threshold conversation compaction. Best raw pass@1 on XBOW. | Compaction is heuristic — occasionally drops a fact the agent later needs. |
| `hacksynth` | Planner+summarizer split (arXiv:2412.01778). Best mean cost/solve in our data. Slightly better on L3. | Two LLM calls per iteration; higher latency; worse on L1 where the loss of full reasoning hurts. |

This comparison is reported in the public writeup as a sidebar; the headline numbers are all `single_loop_compact`.
