"""Generate a human-readable Markdown trace report from a scan directory.

Reads ``logs/solver.jsonl`` (full conversation: system prompt, user message,
assistant turns with reasoning + tool calls, tool results) and
``logs/events.jsonl`` (structured events: scan_start/end, llm_call, tool_call,
flag_detected, loop_detected) to produce a single ``report.md`` file inside the
scan directory that can be read or shared without replaying the run.

Usage (CLI):
    python -m solkyn.reporting.report_generator scans/XBEN-029-24
    python -m solkyn.reporting.report_generator scans/  # all sub-dirs
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    """Load a JSONL file into a list of dicts. Returns ``[]`` if missing."""
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def _truncate(text: str, limit: int = 4000) -> str:
    """Truncate long text with a marker so the report stays readable."""
    if len(text) <= limit:
        return text
    head = text[: limit // 2]
    tail = text[-limit // 2 :]
    omitted = len(text) - limit
    return f"{head}\n\n... [{omitted} chars omitted] ...\n\n{tail}"


def _render_tool_call_args(args: Any) -> str:
    """Render a tool-call arguments blob for inclusion in markdown."""
    if not isinstance(args, dict):
        return str(args)
    if "command" in args:
        return f"`bash`\n```bash\n{args['command']}\n```"
    if "path" in args and "content" in args:
        return f"`file_write {args['path']}`\n```\n{_truncate(str(args['content']), 1500)}\n```"
    if "path" in args:
        return f"`file_read {args['path']}`"
    return f"```json\n{json.dumps(args, indent=2, default=str)}\n```"


def _summarise_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Pull a top-level summary out of the events stream."""
    summary: dict[str, Any] = {
        "challenge_id": None,
        "target_url": None,
        "model": None,
        "mode": None,
        "tags": [],
        "level": None,
        "max_iterations": None,
        "success": None,
        "iterations": None,
        "flag": None,
        "total_time": None,
        "input_tokens": 0,
        "output_tokens": 0,
        "tool_calls": 0,
        "loop_nudges": 0,
    }
    for ev in events:
        if ev.get("type") == "scan_start":
            for key in (
                "challenge_id", "target_url", "model", "mode", "tags",
                "level", "max_iterations",
            ):
                if key in ev:
                    summary[key] = ev[key]
        elif ev.get("type") == "scan_end":
            for key in (
                "success", "iterations", "flag", "total_time",
                "input_tokens", "output_tokens", "tool_calls",
            ):
                if key in ev:
                    summary[key] = ev[key]
        elif ev.get("type") == "loop_detected":
            summary["loop_nudges"] += 1
    return summary


def _render_message(msg: dict[str, Any]) -> str:
    """Render a single conversation message as Markdown."""
    role = msg.get("role", "unknown")
    if role == "system":
        # System prompt is huge; show a small preview with line count.
        content = msg.get("content", "")
        line_count = content.count("\n") + 1
        preview = "\n".join(content.splitlines()[:30])
        return (
            f"### System Prompt ({line_count} lines, {len(content):,} chars)\n\n"
            f"<details><summary>Show first 30 lines</summary>\n\n"
            f"```markdown\n{preview}\n```\n\n</details>\n"
        )
    if role == "user":
        content = msg.get("content", "")
        return f"### User Message\n\n```markdown\n{_truncate(content, 6000)}\n```\n"
    if role == "assistant":
        text = msg.get("content") or ""
        rendered = "### Assistant\n"
        if text:
            rendered += f"\n**Reasoning:**\n\n```\n{_truncate(text, 4000)}\n```\n"
        tcs = msg.get("tool_calls") or []
        if tcs:
            rendered += "\n**Tool Calls:**\n"
            for tc in tcs:
                fn = tc.get("function") or tc
                name = fn.get("name", "?")
                args_raw = fn.get("arguments")
                if isinstance(args_raw, str):
                    try:
                        args_obj = json.loads(args_raw)
                    except json.JSONDecodeError:
                        args_obj = {"raw": args_raw}
                else:
                    args_obj = args_raw or {}
                rendered += f"\n- **{name}**\n\n  {_render_tool_call_args(args_obj)}\n"
        return rendered
    if role == "tool":
        content = msg.get("content", "")
        return (
            f"### Tool Result ({len(content):,} chars)\n\n"
            f"```\n{_truncate(content, 4000)}\n```\n"
        )
    return f"### {role}\n\n```\n{_truncate(str(msg), 2000)}\n```\n"


def _truncate_for_block(s: str, limit: int = 4000) -> str:
    return _truncate(s, limit)


def _render_nested_trace(trace: dict[str, Any]) -> str:
    """Render a HackSynth-style nested trace (``{format: 'nested',
    turns: [...], rolling_summary: [...]}``) as Markdown.

    Each turn is rendered as a level-3 heading with collapsible
    ``<details>`` blocks per agent (planner / summarizer) and a final
    execution block (command + output + summary entry)."""
    lines: list[str] = []
    rolling = trace.get("rolling_summary") or []
    if rolling:
        lines.append("### Final Rolling Working Memory\n")
        for i, entry in enumerate(rolling, start=1):
            lines.append(f"{i}. {entry}")
        lines.append("")
    turns = trace.get("turns") or []
    if not turns:
        lines.append("_No turns recorded._")
        return "\n".join(lines)
    for turn in turns:
        idx = turn.get("turn", "?")
        lines.append(f"### Turn {idx}\n")
        for agent in turn.get("agents") or []:
            name = agent.get("name", "?")
            usage = agent.get("usage") or {}
            usage_bit = ""
            if usage:
                usage_bit = (
                    f" — in: {usage.get('input_tokens', 0)} / "
                    f"out: {usage.get('output_tokens', 0)} tokens"
                )
            response = agent.get("response") or ""
            lines.append(
                f"<details><summary><b>{name}</b>{usage_bit}</summary>\n\n"
                f"```\n{_truncate_for_block(response, 4000)}\n```\n\n"
                f"</details>\n"
            )
        execution = turn.get("execution")
        if execution:
            cmd = execution.get("command") or ""
            output = execution.get("output") or ""
            entry = execution.get("summary_entry") or ""
            lines.append("**Execution:**\n")
            lines.append(f"```bash\n{_truncate_for_block(cmd, 2000)}\n```\n")
            lines.append(
                f"<details><summary>Output ({len(output):,} chars)</summary>\n\n"
                f"```\n{_truncate_for_block(output, 4000)}\n```\n\n</details>\n"
            )
            lines.append(f"_Summary entry:_ {entry}\n")
        lines.append("---\n")
    return "\n".join(lines)


def generate_report(scan_dir: Path) -> Path | None:
    """Generate ``report.md`` inside ``scan_dir``. Returns the path written, or
    ``None`` if there are no logs to report on."""
    logs_dir = scan_dir / "logs"
    solver_log = logs_dir / "solver.jsonl"
    events_log = logs_dir / "events.jsonl"

    messages = _load_jsonl(solver_log)
    events = _load_jsonl(events_log)
    #  nested-format conversation.json (HackSynth) is sufficient
    # to produce a report even when solver.jsonl is empty.
    has_nested_conversation = (scan_dir / "conversation.json").exists() and (
        '"format": "nested"' in (scan_dir / "conversation.json").read_text()
        if (scan_dir / "conversation.json").exists()
        else False
    )
    if not messages and not events and not has_nested_conversation:
        return None

    summary = _summarise_events(events)

    #  surface the per-attempt canary string from stats.json so reports
    # can be cross-referenced for training-data leak detection.
    canary: str | None = None
    cost_usd: float | None = None
    stats_path = scan_dir / "stats.json"
    if stats_path.exists():
        try:
            stats = json.loads(stats_path.read_text())
            canary = stats.get("canary")
            cost_usd = stats.get("cost_usd")
        except (json.JSONDecodeError, OSError):
            pass

    out_lines: list[str] = []
    out_lines.append(f"# Solkyn Trace — {summary.get('challenge_id') or scan_dir.name}\n")

    out_lines.append("## Summary\n")
    out_lines.append("| Field | Value |\n|---|---|")
    out_lines.append(f"| Result | {'✅ PASS' if summary.get('success') else '❌ FAIL'} |")
    out_lines.append(f"| Mode | `{summary.get('mode') or 'unknown'}` |")
    out_lines.append(f"| Model | `{summary.get('model') or 'unknown'}` |")
    out_lines.append(f"| Target | `{summary.get('target_url') or 'unknown'}` |")
    out_lines.append(f"| Level | {summary.get('level') or 'unknown'} |")
    tag_csv = ", ".join(summary.get("tags") or []) or "—"
    out_lines.append(f"| Scope tags | {tag_csv} |")
    out_lines.append(
        f"| Iterations | {summary.get('iterations') or 0} / {summary.get('max_iterations') or '?'} |"
    )
    out_lines.append(f"| Tool calls | {summary.get('tool_calls') or 0} |")
    out_lines.append(f"| Loop nudges | {summary.get('loop_nudges') or 0} |")
    out_lines.append(
        f"| Tokens | {summary.get('input_tokens') or 0:,} in / "
        f"{summary.get('output_tokens') or 0:,} out |"
    )
    out_lines.append(f"| Total time | {summary.get('total_time') or 0:.1f}s |")
    if summary.get("flag"):
        out_lines.append(f"| Flag | `{summary['flag']}` |")
    if cost_usd is not None:
        out_lines.append(f"| Cost | ${cost_usd:.4f} |")
    if canary:
        out_lines.append(f"| Canary | `{canary}` |")
    out_lines.append("")

    # Per-iteration timeline from events.jsonl
    if events:
        out_lines.append("## Timeline\n")
        out_lines.append("| t (s) | Iter | Event | Detail |")
        out_lines.append("|---|---|---|---|")
        for ev in events:
            t = ev.get("elapsed", 0)
            iter_num = ev.get("iteration", "")
            etype = ev.get("type", "")
            detail = ""
            if etype == "tool_call":
                cmd = ev.get("command") or ev.get("tool", "")
                detail = f"`{cmd[:120]}` → {ev.get('result_length', 0)} chars"
            elif etype == "llm_call":
                detail = (
                    f"{ev.get('input_tokens', 0)} in / {ev.get('output_tokens', 0)} out, "
                    f"{ev.get('duration', 0)}s"
                )
            elif etype == "flag_detected":
                detail = f"flag in {ev.get('source', '?')}"
            elif etype == "loop_detected":
                detail = f"nudge #{ev.get('nudge_number', '?')}"
            elif etype == "scan_end":
                detail = "PASS" if ev.get("success") else "FAIL"
            out_lines.append(f"| {t:.1f} | {iter_num} | {etype} | {detail} |")
        out_lines.append("")

    # Full conversation transcript — prefer nested form when
    # ``conversation.json`` exists with ``format: nested`` (HackSynth
    # solver). Otherwise fall back to the flat ``solver.jsonl`` view.
    out_lines.append("## Full Conversation\n")
    nested_trace: dict[str, Any] | None = None
    conversation_path = scan_dir / "conversation.json"
    if conversation_path.exists():
        try:
            data = json.loads(conversation_path.read_text())
            if isinstance(data, dict) and data.get("format") == "nested":
                nested_trace = data
        except (json.JSONDecodeError, OSError):
            nested_trace = None
    if nested_trace is not None:
        out_lines.append(_render_nested_trace(nested_trace))
    elif not messages:
        out_lines.append("_No conversation log found._")
    else:
        for msg in messages:
            out_lines.append(_render_message(msg))
            out_lines.append("---\n")

    report_path = scan_dir / "report.md"
    report_path.write_text("\n".join(out_lines))
    return report_path


def _iter_scan_dirs(root: Path) -> list[Path]:
    """Return scan dirs under ``root`` (or just [root] if it looks like one)."""
    if (root / "logs").exists():
        return [root]
    return [d for d in sorted(root.iterdir()) if d.is_dir() and (d / "logs").exists()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate Markdown trace reports for Solkyn scans.")
    parser.add_argument("path", help="Scan directory (with logs/) or parent directory of scans.")
    args = parser.parse_args(argv)

    root = Path(args.path)
    if not root.exists():
        print(f"Path not found: {root}", file=sys.stderr)
        return 1

    targets = _iter_scan_dirs(root)
    if not targets:
        print(f"No scan directories with logs/ found under {root}", file=sys.stderr)
        return 1

    written = 0
    for scan_dir in targets:
        report_path = generate_report(scan_dir)
        if report_path:
            print(f"wrote {report_path}")
            written += 1
        else:
            print(f"skipped {scan_dir} (no logs)")
    print(f"\nGenerated {written} report(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
