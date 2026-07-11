"""Jinja2 prompt composition and canary tests.

Verifies that:
  - Default prompt rendering is byte-identical to the previous string-concat
    output (frozen via reference hashes captured before the refactor).
  - Optional slots (canary, progress_content, custom_instructions) are appended
    cleanly when provided and produce no output when omitted.
  - ``disable_playbooks=True`` strips the playbook section entirely.
  - ``generate_canary`` returns a fresh prefixed UUID.
"""

from __future__ import annotations

import re

import pytest

from solkyn.agents.prompt_builder import build_solver_prompt, generate_canary

# Frozen reference SHA-256 prefixes for the rendered prompt.
# Originally captured previous to verify the Jinja refactor was byte-identical.
# Subsequently updated for *intentional* prompt edits — when the prompt content
# legitimately changes, recompute hashes via:
#   python -c "import hashlib; from solkyn.agents.prompt_builder import build_solver_prompt; \
#              p=build_solver_prompt('http://t','desc'); \
#              print(len(p), hashlib.sha256(p.encode()).hexdigest()[:16])"
_FROZEN_HASHES = {
    "default": (177181, "726fd1663bbcf7ce"),
    "blackbox": (177181, "726fd1663bbcf7ce"),
}


class TestPromptRenderingParity:
    def test_default_byte_identical_to_pre_refactor(self):
        import hashlib
        p = build_solver_prompt("http://t", "desc")
        assert len(p) == _FROZEN_HASHES["default"][0]
        assert hashlib.sha256(p.encode()).hexdigest()[:16] == _FROZEN_HASHES["default"][1]

    def test_blackbox_byte_identical_to_pre_refactor(self):
        import hashlib
        p = build_solver_prompt("http://t", "desc", mode="blackbox")
        assert len(p) == _FROZEN_HASHES["blackbox"][0]
        assert hashlib.sha256(p.encode()).hexdigest()[:16] == _FROZEN_HASHES["blackbox"][1]

    def test_omitted_optional_slots_produce_no_residue(self):
        """Without canary/progress/custom_instructions, no <!-- canary -->,
        no '## Progress', no '## Additional Instructions' text appears."""
        p = build_solver_prompt("http://t", "desc")
        assert "<!-- canary:" not in p
        assert "## Progress from Previous Attempt" not in p
        assert "## Additional Instructions" not in p


class TestT201Canary:
    def test_generate_canary_format(self):
        c = generate_canary()
        assert c.startswith("solkyn-canary-")
        # 32 hex chars (UUID4 hex form)
        assert re.fullmatch(r"solkyn-canary-[0-9a-f]{32}", c)

    def test_generate_canary_uniqueness(self):
        canaries = {generate_canary() for _ in range(10)}
        assert len(canaries) == 10

    def test_canary_embedded_when_provided(self):
        c = "solkyn-canary-deadbeef" * 2
        p = build_solver_prompt("http://t", "desc", canary=c)
        assert f"<!-- canary: {c} -->" in p

    def test_canary_appended_at_tail(self):
        c = generate_canary()
        p = build_solver_prompt("http://t", "desc", canary=c)
        # Canary lives in the last meaningful line.
        assert p.rstrip().endswith(f"<!-- canary: {c} -->")


class TestT201OptionalSlots:
    def test_progress_content_inserted(self):
        p = build_solver_prompt(
            "http://t", "desc",
            progress_content="Tried sqlmap on /login — 403; pivot to /api next.",
        )
        assert "## Progress from Previous Attempt" in p
        assert "Tried sqlmap on /login" in p

    def test_custom_instructions_inserted(self):
        p = build_solver_prompt(
            "http://t", "desc",
            custom_instructions="Bias toward time-based blind techniques.",
        )
        assert "## Additional Instructions" in p
        assert "Bias toward time-based blind techniques." in p

    def test_disable_playbooks_strips_playbook_section(self):
        p = build_solver_prompt("http://t", "desc", disable_playbooks=True)
        assert "## Vulnerability Playbooks" not in p
        # Solver identity / methodology should still be present.
        assert "Solkyn" in p

    def test_disable_playbooks_suppresses_priority_directive(self):
        p = build_solver_prompt(
            "http://t", "desc",
            tags=["sqli"], disable_playbooks=True,
        )
        # When playbooks are off, tag-based steering loses its anchor — drop it.
        assert "PRIORITY DIRECTIVE" not in p
        assert "## Vulnerability Playbooks" not in p

    def test_all_slots_combined_produce_expected_sections(self):
        c = generate_canary()
        p = build_solver_prompt(
            "http://t", "desc",
            tags=["sqli"],
            progress_content="prev attempt hit a WAF on /search",
            custom_instructions="prefer raw curl over sqlmap",
            canary=c,
        )
        # Every section must appear in stable order.
        idx = [
            p.index("Solkyn"),
            p.index("## Vulnerability Playbooks"),
            p.index("PRIORITY DIRECTIVE"),
            p.index("## Progress from Previous Attempt"),
            p.index("## Additional Instructions"),
            p.index(f"<!-- canary: {c} -->"),
        ]
        assert idx == sorted(idx), f"sections out of order: {idx}"


class TestT201BackwardsCompat:
    """All previous test_prompts.py scenarios still pass — verified via the
    existing ``tests/unit/test_prompts.py`` suite. This file adds specific
    coverage only."""

    @pytest.mark.parametrize("tags,expected_in", [
        (["sqli"], "SQL Injection"),
        (["command_injection"], "Command Injection"),
        (["ssrf"], "SSRF"),
        (["idor"], "IDOR"),
        (["ssti"], "SSTI"),
    ])
    def test_per_tag_playbook_selection_unchanged(self, tags, expected_in):
        p = build_solver_prompt("http://t", "desc", tags=tags)
        assert expected_in in p
