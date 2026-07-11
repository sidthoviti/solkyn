"""Progress summariser — .

After a non-success agent attempt, render the conversation through a Jinja
template and ask the LLM for a structured Markdown report (`progress.md`)
that captures attempted approaches, dead-ends, and the most promising leads
so a *subsequent* attempt can pick up where this one left off.

The summariser uses the same LLM client as the solver but issues a single
non-tool-using `chat()` call. Output is the LLM's raw markdown content; we
don't post-process it (the model is instructed to emit Markdown directly).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

logger = logging.getLogger(__name__)

_TEMPLATE_DIR = Path(__file__).parent / "prompts" / "reporting"
_TEMPLATE_NAME = "progress_template.md.j2"

_JINJA_ENV = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    undefined=StrictUndefined,
    keep_trailing_newline=False,
    autoescape=False,
)

# Limit transcript size fed to the summariser. Most provider context windows
# can absorb ~200KB; we cap at 80KB to leave headroom for output and avoid
# blowing budget on the summariser itself. Trim from the *front* so we keep
# the most recent (and usually most informative) turns.
_MAX_TRANSCRIPT_CHARS = 80_000


def _format_transcript(messages: list[dict[str, Any]]) -> str:
    """Render conversation messages into a compact text transcript.

    System messages are skipped (they're already known to the summariser via
    the target/description fields). Long content is truncated per-message to
    avoid one mega-output dominating the report.
    """
    lines: list[str] = []
    for msg in messages:
        role = msg.get("role", "?")
        if role == "system":
            continue
        content = msg.get("content", "") or ""
        if isinstance(content, list):
            # Some providers return content as a list of typed parts.
            content = " ".join(
                p.get("text", "") if isinstance(p, dict) else str(p) for p in content
            )
        if len(content) > 4000:
            content = content[:4000] + f"\n... [{len(content) - 4000} chars truncated]"
        # Tool calls embedded on assistant messages — surface them so the
        # summariser sees what was attempted, not just the prose around it.
        tool_calls = msg.get("tool_calls") or []
        tc_summary = ""
        if tool_calls:
            tc_lines = []
            for tc in tool_calls:
                tc_args = tc.get("arguments", tc.get("function", {}).get("arguments", {}))
                tc_lines.append(f"  → {tc.get('name', '?')}({str(tc_args)[:200]})")
            tc_summary = "\n" + "\n".join(tc_lines)
        lines.append(f"[{role}] {content}{tc_summary}")
    transcript = "\n\n".join(lines)
    if len(transcript) > _MAX_TRANSCRIPT_CHARS:
        # Keep tail (most recent activity).
        transcript = (
            f"... [transcript head truncated, {len(transcript) - _MAX_TRANSCRIPT_CHARS} chars dropped]\n\n"
            + transcript[-_MAX_TRANSCRIPT_CHARS:]
        )
    return transcript


def render_progress_prompt(
    *,
    target_url: str,
    description: str,
    iterations: int,
    exit_reason: str,
    messages: list[dict[str, Any]],
    tags: list[str] | None = None,
) -> str:
    """Render the Jinja template that becomes the summariser's user prompt."""
    template = _JINJA_ENV.get_template(_TEMPLATE_NAME)
    return template.render(
        target_url=target_url,
        description=description,
        iterations=iterations,
        exit_reason=exit_reason,
        tags=tags or [],
        transcript=_format_transcript(messages),
    )


def generate_progress_summary(
    llm: Any,
    *,
    target_url: str,
    description: str,
    iterations: int,
    exit_reason: str,
    messages: list[dict[str, Any]],
    tags: list[str] | None = None,
) -> str:
    """Call the LLM to produce a structured progress.md.

    Returns the markdown body (LLM `content` string). Raises on LLM error —
    callers should wrap and degrade gracefully (a missing progress.md
    shouldn't crash the run).
    """
    prompt = render_progress_prompt(
        target_url=target_url,
        description=description,
        iterations=iterations,
        exit_reason=exit_reason,
        messages=messages,
        tags=tags,
    )
    logger.info(
        "Generating progress.md summary (transcript=%d chars, iterations=%d, exit=%s)",
        len(prompt), iterations, exit_reason,
    )
    response = llm.chat(
        [
            {
                "role": "system",
                "content": (
                    "You are a senior penetration tester. Produce a precise, "
                    "actionable progress report from a failed attempt's trace. "
                    "Output Markdown only."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        tools=None,
    )
    body = (response.get("content") or "").strip()
    if not body:
        raise RuntimeError("Summariser LLM returned empty content")
    return body


def write_progress_md(attempt_dir: Path, body: str) -> Path:
    """Write the summary to ``<attempt_dir>/progress.md`` and return its path."""
    attempt_dir.mkdir(parents=True, exist_ok=True)
    path = attempt_dir / "progress.md"
    path.write_text(body, encoding="utf-8")
    return path


def load_progress_md(source: str | Path) -> str:
    """Load progress.md content from either a file or a directory containing it.

    Used by ``--resume-from`` to feed prior progress into the next attempt's
    system prompt via the ``progress_content`` Jinja slot.
    """
    p = Path(source)
    if p.is_dir():
        p = p / "progress.md"
    if not p.exists():
        raise FileNotFoundError(f"progress.md not found at {p}")
    return p.read_text(encoding="utf-8")
