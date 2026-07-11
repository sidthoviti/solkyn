"""Prompt builder — assemble the solver system prompt with relevant playbooks.

: rendering switched from string-concat to Jinja2 (``generic_prompt.yaml.j2``).
The default case (no canary / progress / custom_instructions) produces byte-identical
output to the pre-refactor version; new optional slots are appended cleanly when set.
"""

from __future__ import annotations

import uuid
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

_PROMPTS_DIR = Path(__file__).parent / "prompts"

_JINJA_ENV = Environment(
    loader=FileSystemLoader(str(_PROMPTS_DIR)),
    undefined=StrictUndefined,
    keep_trailing_newline=False,
    autoescape=False,
)
_TEMPLATE_NAME = "generic_prompt.yaml.j2"


def generate_canary() -> str:
    """Return a fresh per-run canary string (UUID4, hex form, ``solkyn-canary-`` prefixed).

    Embedded into the system prompt and saved into reports so we can detect
    later if any verbatim trace content shows up in model training data.
    """
    return f"solkyn-canary-{uuid.uuid4().hex}"

# All known playbooks (used as the "load-all" fallback for unknown tags / blackbox runs).
_ALL_PLAYBOOKS: tuple[str, ...] = (
    "playbook_sqli.md",
    "playbook_cmdi.md",
    "playbook_xss.md",
    "playbook_ssrf.md",
    "playbook_idor.md",
    "playbook_lfi.md",
    "playbook_ssti.md",
    "playbook_deser.md",
    "playbook_smuggling.md",
    "playbook_race.md",
    "playbook_general.md",
)

# Map vulnerability tags to playbook files. Tag names follow OWASP/CWE conventions
# (sqli, command_injection, xss, etc.) and overlap with XBOW tag names. Tags are
# matched case-insensitively after normalising separators ('-' / ' ' → '_').
_TAG_TO_PLAYBOOK: dict[str, str] = {
    # SQL & query injection
    "sqli": "playbook_sqli.md",
    "sql_injection": "playbook_sqli.md",
    "blind_sqli": "playbook_sqli.md",
    "nosqli": "playbook_sqli.md",
    "nosql_injection": "playbook_sqli.md",
    "graphql": "playbook_sqli.md",
    # Command injection
    "command_injection": "playbook_cmdi.md",
    "cmdi": "playbook_cmdi.md",
    "rce": "playbook_cmdi.md",
    "os_command_injection": "playbook_cmdi.md",
    # XSS
    "xss": "playbook_xss.md",
    "cross_site_scripting": "playbook_xss.md",
    "stored_xss": "playbook_xss.md",
    "reflected_xss": "playbook_xss.md",
    "dom_xss": "playbook_xss.md",
    # SSRF
    "ssrf": "playbook_ssrf.md",
    "server_side_request_forgery": "playbook_ssrf.md",
    # IDOR / authn / authz
    "idor": "playbook_idor.md",
    "broken_access_control": "playbook_idor.md",
    "privilege_escalation": "playbook_idor.md",
    "http_method_tamper": "playbook_idor.md",
    "jwt": "playbook_idor.md",
    "default_credentials": "playbook_idor.md",
    "auth_bypass": "playbook_idor.md",
    # SSTI
    "ssti": "playbook_ssti.md",
    "server_side_template_injection": "playbook_ssti.md",
    "template_injection": "playbook_ssti.md",
    # Deserialization
    "insecure_deserialization": "playbook_deser.md",
    "deserialization": "playbook_deser.md",
    "pickle": "playbook_deser.md",
    "unserialize": "playbook_deser.md",
    # File upload / inclusion
    "arbitrary_file_upload": "playbook_general.md",
    "file_upload": "playbook_general.md",
    "lfi": "playbook_lfi.md",
    "local_file_inclusion": "playbook_lfi.md",
    "rfi": "playbook_lfi.md",
    "path_traversal": "playbook_lfi.md",
    "directory_traversal": "playbook_lfi.md",
    "information_disclosure": "playbook_lfi.md",
    "ssh": "playbook_lfi.md",
    # XXE / misc
    "xxe": "playbook_general.md",
    "crypto": "playbook_general.md",
    "business_logic": "playbook_general.md",
    "cve": "playbook_general.md",
    # Race / smuggling
    "race_condition": "playbook_race.md",
    "smuggling_desync": "playbook_smuggling.md",
    "request_smuggling": "playbook_smuggling.md",
    "http_smuggling": "playbook_smuggling.md",
}

# Lightweight fuzzy keywords used when an exact tag match fails. Each substring,
# if found in the normalised tag, maps to a playbook.
_FUZZY_KEYWORDS: tuple[tuple[str, str], ...] = (
    ("sql", "playbook_sqli.md"),
    ("nosql", "playbook_sqli.md"),
    ("graphql", "playbook_sqli.md"),
    ("command", "playbook_cmdi.md"),
    ("rce", "playbook_cmdi.md"),
    ("xss", "playbook_xss.md"),
    ("ssrf", "playbook_ssrf.md"),
    ("forg", "playbook_ssrf.md"),
    ("idor", "playbook_idor.md"),
    ("access", "playbook_idor.md"),
    ("authz", "playbook_idor.md"),
    ("jwt", "playbook_idor.md"),
    ("auth", "playbook_idor.md"),
    ("ssti", "playbook_ssti.md"),
    ("template", "playbook_ssti.md"),
    ("deserial", "playbook_deser.md"),
    ("pickle", "playbook_deser.md"),
    ("upload", "playbook_general.md"),
    ("lfi", "playbook_lfi.md"),
    ("rfi", "playbook_lfi.md"),
    ("travers", "playbook_lfi.md"),
    ("inclusion", "playbook_lfi.md"),
    ("disclosure", "playbook_lfi.md"),
    ("race", "playbook_race.md"),
    ("smuggl", "playbook_smuggling.md"),
    ("desync", "playbook_smuggling.md"),
    ("xxe", "playbook_general.md"),
    ("crypto", "playbook_general.md"),
    ("cve", "playbook_general.md"),
)


def _normalise_tag(tag: str) -> str:
    """Lower-case the tag and collapse separators to underscores."""
    return tag.strip().lower().replace("-", "_").replace(" ", "_")


def _resolve_tags(tags: list[str]) -> set[str]:
    """Map a list of raw tag strings to a set of playbook filenames.

    1. Exact match against ``_TAG_TO_PLAYBOOK`` (after normalising case/separators).
    2. Fallback to fuzzy substring keywords.
    3. If still no matches at all, returns an empty set so the caller can decide
       to load every playbook.
    """
    playbooks: set[str] = set()
    for raw in tags:
        norm = _normalise_tag(raw)
        if norm in _TAG_TO_PLAYBOOK:
            playbooks.add(_TAG_TO_PLAYBOOK[norm])
            continue
        for needle, pb in _FUZZY_KEYWORDS:
            if needle in norm:
                playbooks.add(pb)
                break
    return playbooks


def _load_prompt_file(filename: str) -> str:
    """Load a prompt file from the prompts directory."""
    path = _PROMPTS_DIR / filename
    return path.read_text().strip()


def build_solver_prompt(
    target_url: str,
    description: str,
    tags: list[str] | None = None,
    files: list[str] | None = None,
    mode: str = "whitebox",
    *,
    disable_playbooks: bool = False,
    progress_content: str | None = None,
    custom_instructions: str | None = None,
    canary: str | None = None,
) -> str:
    """Build the full solver system prompt via Jinja2 (``generic_prompt.yaml.j2``).

    Args:
        target_url: The target URL to attack.
        description: Challenge/target description.
        tags: Optional vulnerability tags to select relevant playbooks.
              When None / empty / no match → load all playbooks for full coverage.
        files: Optional list of relevant filenames (currently unused at system-prompt
               level — included for the user-message slot built by the caller).
        mode: Test mode — "whitebox", "greybox", or "blackbox". In "blackbox" the
              tag-priority directive is suppressed (the agent should reason about
              the vulnerability class itself) and all playbooks are loaded.
        disable_playbooks: When True, omit the playbook block entirely ( A/B).
        progress_content: Optional content to inject from a previous attempt's
                          ``progress.md`` ( resume).
        custom_instructions: Optional per-run instructions appended after playbooks.
        canary: Optional per-run UUID embedded as an HTML comment for trace
                integrity / training-data leak detection.

    Returns:
        Complete system prompt string.
    """
    system_text = _load_prompt_file("solver_system.md")

    # ------------------------------------------------------------------
    # Resolve which playbooks to include.
    # ------------------------------------------------------------------
    playbook_files: set[str]
    if disable_playbooks:
        playbook_files = set()
    elif mode == "blackbox" or not tags:
        playbook_files = set(_ALL_PLAYBOOKS)
    else:
        playbook_files = _resolve_tags(tags)
        # Always include the general fallback so universal techniques are present.
        playbook_files.add("playbook_general.md")
        # If tag resolution found nothing useful, fall back to loading everything.
        if playbook_files == {"playbook_general.md"} and tags:
            playbook_files = set(_ALL_PLAYBOOKS)

    playbook_texts = [_load_prompt_file(pf) for pf in sorted(playbook_files)]

    # ------------------------------------------------------------------
    # Tag-emphasis directive — only when tags supplied and not blackbox.
    # ------------------------------------------------------------------
    priority_directive: str | None = None
    if tags and mode != "blackbox" and not disable_playbooks:
        tag_list = ", ".join(tags)
        priority_directive = (
            f"Engagement scope tags: **[{tag_list}]**. "
            f"Try {tag_list}-related techniques FIRST before exploring other vulnerability classes. "
            f"If a technique fails after 3 attempts, try the NEXT technique from the same playbook "
            f"before pivoting to a different class."
        )

    template = _JINJA_ENV.get_template(_TEMPLATE_NAME)
    return template.render(
        system=system_text,
        playbooks=playbook_texts,
        priority_directive=priority_directive,
        progress_content=progress_content,
        custom_instructions=custom_instructions,
        canary=canary,
    )
