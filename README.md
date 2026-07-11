# Solkyn

Solkyn is an experimental **autonomous web-pentesting agent and benchmark harness** for controlled labs and authorized security testing. It puts a large language model in an observe–act loop with real tools inside an isolated Kali Linux container, records every attempt as auditable artifacts, and turns benchmark sweeps into reproducible pass@k, per-level, per-class, cost, token, and refusal summaries.

It was built to answer a narrow research question — *if you hold the agent harness fixed and swap only the underlying model, what actually changes?* — and the write-up of that experiment is here:

> **Blog post: [The Solkyn Experiment — Models Tie, Systems Decide](https://sidthoviti.com/the-solkyn-experiment-models-tie-systems-decide/)**

---

## Quick Summary of Results

In a **source-aware whitebox** run of the 104-challenge [XBOW validation suite](https://github.com/xbow-engineering/validation-benchmarks), using the same Solkyn single-agent harness and **three attempts per challenge**, three frontier models produced closely clustered *verified* results (scored on real flag matches, not model-claimed flags):

| Model | pass@1 | pass@3 |
|---|---:|---:|
| `gpt-5.4` | 92/104 | 95/104 |
| `Kimi-K2.6` | 92/104 | 96/104 |
| `DeepSeek-V4-Pro` | 92/104 | 98/104 |
| **Three-model union** | — | **99/104** |

The headline is a **tie on first-attempt capability** — all three solve exactly 92/104 — with the real differences showing up in *efficiency* (iterations-to-solve), retry behavior, and provider refusal behavior rather than raw solve rate. These numbers are a source-aware benchmark snapshot, **not** a blackbox pentest result or a universal model ranking. Full methodology, caveats, and analysis are in the [blog post](https://sidthoviti.com/the-solkyn-experiment-models-tie-systems-decide/); the machine-readable summaries live in [`results/`](results/) and the challenge inventory in [`docs/xbow-challenge-inventory.json`](docs/xbow-challenge-inventory.json).

---

## How It Works

Solkyn is deliberately simple: **one model, one loop, one tool surface.** That minimalism is the point — it makes a model swap a clean intervention.

### The agent loop

At its core Solkyn runs a single `while` loop (the *solver*). Each iteration:

1. Sends the system prompt + full conversation history (with tool schemas) to the model.
2. Executes the tool calls the model returns.
3. Appends the tool output back into the conversation.
4. Scans the output for the target flag pattern.
5. Repeats until the flag is found or a budget/termination condition is hit.

An *orchestrator* wraps the solver to enforce iteration and time budgets, apply stuck-handling nudges, and record artifacts.

### Tools (run inside a Kali container)

All tool execution happens inside an isolated Kali Linux Docker container via `docker exec`, so the agent never touches the host:

- `bash_exec` — arbitrary shell: `curl`, `nmap`, `sqlmap`, `ffuf`, Python, etc.
- `file_read` / `file_write` — read target source and stage exploit scripts.
- A **browser helper** for DOM-dependent challenges.
- An **out-of-band (OOB) callback catcher** — a small HTTP listener, reachable from the target, that confirms *blind* vulnerabilities (blind SSRF/XXE/RCE, RFI, DNS exfiltration) by observing an inbound callback instead of a direct response.

### Prompt scaffolding

- **Vulnerability-class playbooks.** Eleven short Markdown checklists ship with the harness — ten class-specific (XSS, SQLi, SSTI, IDOR, LFI, command injection, deserialization, SSRF, request smuggling, race conditions) plus a `general` fallback. A challenge's tags select which playbooks are concatenated into the system prompt.
- **Continuation nudges.** If the model returns no tool call while budget remains and the flag is unfound, the solver re-injects recent actions and asks for a different approach (capped per run), plus a one-shot "try-harder" re-engagement.
- **Stagnation nudges.** The orchestrator detects loops (the same normalized command or identical tool-result signature repeated across recent turns) and injects a tactic-change nudge, capped per run.
- **Context compaction.** The `single_loop_compact` solver estimates conversation size and, once it crosses a fraction of the model's context window, summarizes older turns while preserving the most recent ones verbatim and never compacting a flag-bearing message — so long runs don't exhaust the window.

None of this scaffolding reasons *for* the model; it just keeps a single greedy loop from stalling.

### Providers

Models are configured, not hard-coded. Solkyn talks to **OpenAI-compatible** and **Anthropic-style** endpoints, including Azure AI Foundry deployments and local OpenAI-compatible servers (e.g. LM Studio). Endpoint, key, model name, sampling params, and per-token pricing are all set in configuration.

### Artifacts and scoring

Every attempt writes a directory of auditable artifacts: a per-attempt `manifest.jsonl` row, `stats.json` (exit reason, iterations, duration, token accounting, cost), a typed `events.jsonl` stream, the full role-tagged transcript, and human-readable reports. Scoring uses the **verified `success` field** (the submitted flag matches the build's secret flag), never the model's self-reported `flag_found`, which can be fooled by decoy flags planted in some challenges.

### Aggregation

`scripts/aggregate_results.py` turns a sweep's manifests into the summaries under [`results/`](results/): a leaderboard, per-level and per-class breakdowns, an unsolved set, refusal counts, and an `aggregate-summary.json`.

---

## Installation

Requirements:

- Python 3.11+
- Docker
- A supported LLM provider (OpenAI-compatible or Anthropic-style) or a local OpenAI-compatible endpoint

Install the package and copy the config templates:

```bash
python -m pip install -e ".[dev]"
cp .env.example .env
cp configs/default.example.yaml configs/default.yaml
```

Edit `.env` and `configs/default.yaml` with your provider endpoint, API key, model name, and pricing. Both `.env` and `configs/default.yaml` are git-ignored so your credentials never get committed — only the `.example` templates are tracked.

Build the Kali tool container:

```bash
make docker-build
```

Verify the install:

```bash
pytest
ruff check .
```

---

## Usage

Run a single challenge or target through the challenge runner:

```bash
python scripts/run_challenges.py --help
```

Run a full benchmark sweep (multiple challenges, multiple attempts):

```bash
python scripts/run_full_sweep.py --help
```

Aggregate a completed sweep into the `results/` summaries:

```bash
python scripts/aggregate_results.py --help
```

Sweeps are resume-safe: each leg writes an append-only manifest and the runner skips already-completed `(challenge, attempt)` pairs, so a run can be killed and restarted without double-counting.

---

## Repository Layout

| Path | Contents |
|---|---|
| `solkyn/` | The agent: solvers, orchestrator, tools, LLM providers, config, reporting. |
| `scripts/` | Entry points for running challenges, full sweeps, and aggregation. |
| `configs/` | Configuration templates (`*.example.*`); your real `default.yaml` stays local. |
| `docker/` | Kali tool-container image and helper scripts. |
| `results/` | Sanitized aggregate summaries: leaderboard, per-level, per-class, refusals, unsolved, JSON. |
| `scans/` | Curated single-challenge smoke-test runs (`public_smoke`, `public_smoke_azure`) — full per-attempt artifacts as a worked example. |
| `docs/` | Results summary and the XBOW challenge inventory. |
| `tests/` | Unit and integration tests. |

---

## License

Released under the [MIT License](LICENSE) — free to use, modify, and distribute with attribution.
