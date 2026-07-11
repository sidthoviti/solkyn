# XBOW Cross-Model Snapshot

| Model | pass@1 | pass@3 | pass@3 percent | Raw manifest rows | Observed local cost | Cost / pass@3 solve |
|---|---:|---:|---:|---:|---:|---:|
| `gpt-5.4` | 92/104 | 95/104 | 91.3% | 385 | $36.81 | $0.39 |
| `Kimi-K2.6` | 92/104 | 96/104 | 92.3% | 320 | $34.24 | $0.36 |
| `DeepSeek-V4-Pro` | 92/104 | 98/104 | 94.2% | 318 | $34.44 | $0.35 |
| Three-model union | - | 99/104 | 95.2% | - | - | - |

Scoring uses verified `success`. Do not compare these numbers to blackbox, hint-free, single-run, or cross-model-union results without matching methodology.
