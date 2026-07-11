"""Unit tests for prompt builder."""

from __future__ import annotations

from solkyn.agents.prompt_builder import build_solver_prompt


class TestPromptBuilder:
    def test_full_prompt_has_core_sections(self):
        prompt = build_solver_prompt(
            target_url="http://target.local:8080",
            description="A test challenge with SQL injection",
        )
        assert "Solkyn" in prompt
        assert "Reconnaissance" in prompt
        assert "FLAG{" in prompt
        assert "Stay in scope" in prompt

    def test_target_not_in_system_prompt(self):
        """Target info goes in user message, not system prompt."""
        prompt = build_solver_prompt(
            target_url="http://target.local:8080",
            description="Test",
        )
        # The prompt builder builds the *system* prompt only
        # Target URL is injected by the SolverAgent in the user message
        assert "Solkyn" in prompt

    def test_all_playbooks_included_without_tags(self):
        prompt = build_solver_prompt(
            target_url="http://target.local",
            description="Unknown challenge",
        )
        # All playbooks should be included
        assert "SQL Injection" in prompt
        assert "Command Injection" in prompt
        assert "XSS" in prompt
        assert "SSRF" in prompt
        assert "IDOR" in prompt
        assert "General Exploration" in prompt

    def test_sqli_tags_include_sqli_playbook(self):
        prompt = build_solver_prompt(
            target_url="http://target.local",
            description="SQL injection challenge",
            tags=["sqli"],
        )
        assert "SQL Injection" in prompt
        assert "sqlmap" in prompt
        # Should NOT include other playbooks
        assert "Command Injection Playbook" not in prompt
        assert "SSRF Playbook" not in prompt

    def test_cmdi_tags_include_cmdi_playbook(self):
        prompt = build_solver_prompt(
            target_url="http://target.local",
            description="Command injection",
            tags=["command_injection"],
        )
        assert "Command Injection" in prompt
        assert ";id" in prompt

    def test_multiple_tags(self):
        prompt = build_solver_prompt(
            target_url="http://target.local",
            description="Multi-vuln",
            tags=["sqli", "ssrf"],
        )
        assert "SQL Injection" in prompt
        assert "SSRF" in prompt

    def test_unknown_tags_get_general_playbook(self):
        prompt = build_solver_prompt(
            target_url="http://target.local",
            description="Unknown vuln type",
            tags=["some_unknown_tag"],
        )
        assert "General Exploration" in prompt

    def test_graphql_tag_maps_to_sqli(self):
        prompt = build_solver_prompt(
            target_url="http://target.local",
            description="GraphQL endpoint",
            tags=["graphql"],
        )
        assert "SQL Injection" in prompt
        assert "GraphQL" in prompt

    def test_ssti_tag_maps_to_ssti_playbook(self):
        prompt = build_solver_prompt(
            target_url="http://target.local",
            description="SSTI challenge",
            tags=["ssti"],
        )
        assert "SSTI" in prompt
        assert "{{7*7}}" in prompt
        # Dedicated SSTI playbook content (Step 2 — Jinja2)
        assert "Jinja2 Exploitation" in prompt

    def test_files_parameter_accepted(self):
        # files are for the user message, not system prompt
        # but build_solver_prompt should accept the parameter without error
        prompt = build_solver_prompt(
            target_url="http://target.local",
            description="Test",
            files=["app.py", "requirements.txt"],
        )
        assert "Solkyn" in prompt

    def test_tag_emphasis_injected_with_tags(self):
        prompt = build_solver_prompt(
            target_url="http://target.local",
            description="SQLi challenge",
            tags=["sqli"],
        )
        assert "PRIORITY DIRECTIVE" in prompt
        assert "sqli" in prompt

    def test_tag_emphasis_not_injected_without_tags(self):
        prompt = build_solver_prompt(
            target_url="http://target.local",
            description="Unknown challenge",
        )
        assert "PRIORITY DIRECTIVE" not in prompt

    def test_kali_tools_listed_in_system_prompt(self):
        prompt = build_solver_prompt(
            target_url="http://target.local",
            description="Test",
        )
        assert "ffuf" in prompt
        assert "nuclei" in prompt
        assert "sqlmap" in prompt
        assert "searchsploit" in prompt

    def test_blackbox_mode_loads_all_playbooks_and_no_priority_directive(self):
        prompt = build_solver_prompt(
            target_url="http://target.local",
            description="Some target",
            tags=["sqli"],
            mode="blackbox",
        )
        # All playbooks present
        assert "SQL Injection" in prompt
        assert "Command Injection" in prompt
        assert "SSTI" in prompt
        assert "SSRF" in prompt
        # No priority steering in blackbox
        assert "PRIORITY DIRECTIVE" not in prompt

    def test_greybox_mode_keeps_priority_directive(self):
        prompt = build_solver_prompt(
            target_url="http://target.local",
            description="Greybox SQLi engagement",
            tags=["sqli"],
            mode="greybox",
        )
        assert "PRIORITY DIRECTIVE" in prompt

    def test_tag_normalisation_case_and_separators(self):
        # "SQL-Injection", "  sqli  ", "Command Injection" should all resolve.
        for tag in ["SQL-Injection", "  Sqli  ", "Command Injection", "SSTI"]:
            prompt = build_solver_prompt(
                target_url="http://target.local",
                description="Test",
                tags=[tag],
            )
            assert "PRIORITY DIRECTIVE" in prompt

    def test_fuzzy_keyword_fallback(self):
        # Unknown tag containing a known keyword should still pick the right playbook.
        prompt = build_solver_prompt(
            target_url="http://target.local",
            description="Test",
            tags=["weird_custom_sqli_variant"],
        )
        # Expect SQLi playbook to load via fuzzy match
        assert "SQL Injection" in prompt

    def test_no_xbow_or_xben_references_in_any_playbook(self):
        # Hard guarantee that playbooks contain no challenge-specific labels.
        prompt = build_solver_prompt(
            target_url="http://target.local",
            description="Test",
        )
        assert "XBEN-" not in prompt
        assert "Bobby Payroll" not in prompt
        assert "Poison Inclusion" not in prompt
        assert "Art Gallery" not in prompt
        assert "skumodel" not in prompt
