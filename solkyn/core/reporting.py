"""ReportGenerator — generate the three terminal-status artifacts.

Layered on top of :mod:`solkyn.reporting.report_generator`. For each completed
attempt directory, produces:

* ``report.md``       — full structured trace (delegates to existing generator,
                         which now includes the per-run canary string and cost).
* ``summary.md``      — LLM-generated post-engagement narrative (vuln, exploit,
                         key findings, fix). Skipped if no LLM is available.
* ``attack_graph.md`` — LLM-generated Mermaid flowchart of the exploit chain.
                         Skipped if no LLM is available.

The summariser/grapher LLM calls are best-effort — a failure logs a warning and
omits the file rather than crashing the run.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

logger = logging.getLogger(__name__)

_TEMPLATE_DIR = (
    Path(__file__).resolve().parent.parent
    / "agents" / "prompts" / "reporting"
)

_JINJA_ENV = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    undefined=StrictUndefined,
    keep_trailing_newline=False,
    autoescape=False,
)


def _format_transcript_for_llm(messages: list[dict[str, Any]], max_chars: int = 60_000) -> str:
    """Compact, tool-call-aware transcript renderer for LLM input."""
    lines: list[str] = []
    for m in messages:
        role = m.get("role", "?")
        if role == "system":
            continue
        content = m.get("content", "") or ""
        if isinstance(content, list):
            content = " ".join(
                p.get("text", "") if isinstance(p, dict) else str(p) for p in content
            )
        if len(content) > 3000:
            content = content[:3000] + "...[truncated]"
        tcs = m.get("tool_calls") or []
        if tcs:
            tc_str = "; ".join(
                f"{tc.get('name', '?')}({str(tc.get('arguments', ''))[:160]})"
                for tc in tcs
            )
            content = f"{content}\n→ {tc_str}"
        lines.append(f"[{role}] {content}")
    transcript = "\n\n".join(lines)
    if len(transcript) > max_chars:
        transcript = (
            f"... [head truncated, {len(transcript) - max_chars} chars dropped]\n\n"
            + transcript[-max_chars:]
        )
    return transcript


_STATUS_EMOJI = {
    True: "✅",
    False: "❌",
    "time_limit": "⏱️",
    "cost_limit": "💸",
    "error": "💥",
    "max_iterations": "❌",
    "no_tool_calls": "❌",
    "flag_found": "✅",
}


def status_emoji(success: bool, exit_reason: str | None = None) -> str:
    """Pick the right emoji for the terminal status."""
    if success:
        return "✅"
    if exit_reason and exit_reason in _STATUS_EMOJI:
        return str(_STATUS_EMOJI[exit_reason])
    return "❌"


class ReportGenerator:
    """Bundles the three reporting artifacts for a single attempt directory."""

    def __init__(
        self,
        attempt_dir: Path | str,
        llm: Any | None = None,
    ) -> None:
        self.attempt_dir = Path(attempt_dir)
        self.llm = llm

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _load_stats(self) -> dict[str, Any]:
        path = self.attempt_dir / "stats.json"
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return {}

    def _load_conversation(self) -> list[dict[str, Any]]:
        path = self.attempt_dir / "conversation.json"
        if not path.exists():
            # Fall back to logs/solver.jsonl if no conversation.json.
            jsonl = self.attempt_dir / "logs" / "solver.jsonl"
            if not jsonl.exists():
                return []
            out: list[dict[str, Any]] = []
            for line in jsonl.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            return out
        try:
            data = json.loads(path.read_text())
            if isinstance(data, list):
                return data
            return data.get("messages", [])
        except (json.JSONDecodeError, OSError):
            return []

    def _load_config(self) -> dict[str, Any]:
        path = self.attempt_dir / "config.json"
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_report_md(self) -> Path | None:
        """Produce ``report.md`` (delegates to the existing generator which
        now embeds canary + cost from stats.json).
        """
        from solkyn.reporting.report_generator import generate_report
        return generate_report(self.attempt_dir)

    def generate_summary_md(self) -> Path | None:
        """LLM-generated post-engagement summary. Returns the file path or
        None if skipped (no LLM, no conversation, or LLM error).
        """
        if self.llm is None:
            logger.info("generate_summary_md: skipped (no LLM provided)")
            return None
        messages = self._load_conversation()
        if not messages:
            logger.info("generate_summary_md: skipped (no conversation)")
            return None
        stats = self._load_stats()
        config = self._load_config()
        try:
            template = _JINJA_ENV.get_template("summary_template.md.j2")
            prompt = template.render(
                target_url=config.get("target_url", "unknown"),
                status_text=("SUCCESS" if stats.get("success") else "FAILED"),
                flag=stats.get("flag"),
                iterations=stats.get("iterations", 0),
                tool_calls_count=stats.get("tool_calls", 0),
                transcript=_format_transcript_for_llm(messages),
            )
            response = self.llm.chat(
                [
                    {
                        "role": "system",
                        "content": (
                            "You write concise post-engagement summaries for "
                            "pentest CTF results. Output Markdown only."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                tools=None,
            )
            body = (response.get("content") or "").strip()
            if not body:
                raise RuntimeError("empty summary content")
        except Exception as e:
            logger.warning("summary.md generation failed: %s", e)
            return None
        out_path = self.attempt_dir / "summary.md"
        out_path.write_text(body, encoding="utf-8")
        return out_path

    def generate_attack_graph_md(self) -> Path | None:
        """LLM-generated Mermaid flowchart of the exploit chain."""
        if self.llm is None:
            logger.info("generate_attack_graph_md: skipped (no LLM provided)")
            return None
        messages = self._load_conversation()
        if not messages:
            logger.info("generate_attack_graph_md: skipped (no conversation)")
            return None
        stats = self._load_stats()
        config = self._load_config()
        try:
            template = _JINJA_ENV.get_template("attack_graph_template.md.j2")
            prompt = template.render(
                target_url=config.get("target_url", "unknown"),
                status_text=("SUCCESS" if stats.get("success") else "FAILED"),
                transcript=_format_transcript_for_llm(messages),
            )
            response = self.llm.chat(
                [
                    {
                        "role": "system",
                        "content": (
                            "You produce Mermaid flowchart diagrams of pentest "
                            "exploit chains. Output only the fenced mermaid block."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                tools=None,
            )
            body = (response.get("content") or "").strip()
            if not body:
                raise RuntimeError("empty graph content")
        except Exception as e:
            logger.warning("attack_graph.md generation failed: %s", e)
            return None
        out_path = self.attempt_dir / "attack_graph.md"
        out_path.write_text(body, encoding="utf-8")
        return out_path

    def generate_all(self) -> dict[str, Path | None]:
        """Generate all three artifacts. Returns a dict of name → path (or None)."""
        return {
            "report": self.generate_report_md(),
            "summary": self.generate_summary_md(),
            "attack_graph": self.generate_attack_graph_md(),
        }
