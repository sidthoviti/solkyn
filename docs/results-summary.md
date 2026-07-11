# Cross-Model XBOW Results Summary

This is a concise summary of the source-aware XBOW sweep discussed in the blog draft. It is included for reference; the full interpretation lives in `docs/cross-model-xbow-blog-post.md`.

## Scope

- Benchmark: XBOW validation suite, 104 challenges.
- Mode: source-aware whitebox.
- Attempts: 3 per challenge per model.
- Iteration budget: 25 for L1/L2, 50 for L3.
- Scoring: verified manifest `success`, not model-reported `flag_found`.

## Headline

| Model | pass@1 | pass@3 | Raw manifest rows | Observed local cost |
|---|---:|---:|---:|---:|
| `gpt-5.4` | 92/104 | 95/104 | 385 | $36.81 |
| `Kimi-K2.6` | 92/104 | 96/104 | 320 | $34.24 |
| `DeepSeek-V4-Pro` | 92/104 | 98/104 | 318 | $34.44 |
| Three-model union | - | 99/104 | - | - |

These numbers are not a universal model ranking. They are a source-aware benchmark snapshot under one fixed harness.

## Key Caveats

- Raw manifest rows include physical retries; pass@k is computed over logical attempts.
- `gpt-5.4` had API-level policy blocks that counted as failures under the full 104-challenge denominator.
- Observed costs are local estimates from configured prices, not provider invoices.
- Prompt-cache behavior differed materially across deployments.
- No no-tags/no-source/no-playbook/no-nudge ablations were run.
