# Refusal Summary

| Model | API-level policy blocks | In-band refusals | Notes |
|---|---:|---:|---|
| `gpt-5.4` | 64 across 27 challenges | 0 | Provider rejected requests before model completion. |
| `Kimi-K2.6` | 0 | 0 | No meaningful refusal behavior observed in this run. |
| `DeepSeek-V4-Pro` | 0 | 71 | Model emitted soft refusals in-band; the loop usually recovered. |

`gpt-5.4` API-level policy blocks break down into 57 high-risk-cyber blocks across 25 challenges and 7 invalid-prompt blocks across 5 challenges. The union is 27 affected challenges.
