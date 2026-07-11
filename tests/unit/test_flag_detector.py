"""Tests for the flag detector — Phase 7 P0 bugfix.

The original regex ``FLAG\\{[a-fA-F0-9]+\\}`` rejected every real XBOW
flag (UUID-with-hyphens or arbitrary phrase). These tests pin the new
permissive pattern against the actual flag shapes seen in
``benchmarks/xbow/benchmarks/*/docker-compose.yml``.
"""

from __future__ import annotations

import pytest

from solkyn.agents.flag_detector import DEFAULT_PATTERNS, FlagDetector


class TestRealXbowFlagShapes:
    """Real flag shapes harvested from XBOW docker-compose files."""

    def test_uuid_lowercase(self):
        # XBEN-001-24 .. XBEN-104-24 all use this shape.
        det = FlagDetector()
        out = det.scan("Got it: flag{85c0d827-5e28-4577-be2b-319bdcbf872d}")
        assert out == ["flag{85c0d827-5e28-4577-be2b-319bdcbf872d}"]

    def test_uuid_uppercase_prefix(self):
        det = FlagDetector()
        out = det.scan("Result: FLAG{85c0d827-5e28-4577-be2b-319bdcbf872d}")
        assert out == ["FLAG{85c0d827-5e28-4577-be2b-319bdcbf872d}"]

    def test_phrase_with_apostrophe_and_underscore(self):
        # XBEN-061 actual flag.
        det = FlagDetector()
        out = det.scan("decoded: flag{I'm_a_Script_Kiddie}")
        assert out == ["flag{I'm_a_Script_Kiddie}"]

    def test_phrase_with_spaces(self):
        det = FlagDetector()
        out = det.scan("flag{hello world}")
        assert out == ["flag{hello world}"]

    def test_base64_with_padding(self):
        det = FlagDetector()
        out = det.scan("FLAG{SGVsbG8=}")
        assert out == ["FLAG{SGVsbG8=}"]


class TestNonMatching:
    def test_no_flag_text(self):
        det = FlagDetector()
        assert det.scan("nothing here") == []

    def test_open_brace_only(self):
        det = FlagDetector()
        # Without closing brace it should not match.
        assert det.scan("flag{unterminated") == []

    def test_no_prefix(self):
        det = FlagDetector()
        # Bare {foo} without flag/FLAG prefix is not a flag.
        assert det.scan("{just-some-uuid}") == []

    def test_newline_terminates(self):
        det = FlagDetector()
        # Body must not span newlines.
        assert det.scan("flag{abc\n123}") == []


class TestDeduplication:
    def test_repeated_match_returned_once(self):
        det = FlagDetector()
        text = "flag{abcd1234efgh} again flag{abcd1234efgh}"
        assert det.scan(text) == ["flag{abcd1234efgh}"]

    def test_distinct_flags_both_returned(self):
        det = FlagDetector()
        text = "flag{aaaa1111bbbb} and flag{cccc2222dddd}"
        assert det.scan(text) == ["flag{aaaa1111bbbb}", "flag{cccc2222dddd}"]


class TestCustomPatterns:
    def test_user_supplied_patterns_replace_defaults(self):
        det = FlagDetector(patterns=[r"CUSTOM_TOKEN_\d+"])
        assert det.scan("flag{x-1}") == []
        assert det.scan("CUSTOM_TOKEN_42") == ["CUSTOM_TOKEN_42"]


@pytest.mark.parametrize("body", [
    "85c0d827-5e28-4577-be2b-319bdcbf872d",
    "I'm_a_Script_Kiddie",
    "abcdef0123456789",
    "with.dots.in.body",
    "with/slashes/in/body",
    "AbC=+/dEf",  # base64 alphabet + padding
])
def test_default_pattern_matches_diverse_shapes(body):
    det = FlagDetector(DEFAULT_PATTERNS)
    assert det.scan(f"flag{{{body}}}") == [f"flag{{{body}}}"]


class TestPlaceholderRejection:
    """ reject LLM-emitted placeholders that look syntactically like
    flags but cannot be real ones.

    The  L3 sweep showed all 3 challenges fail with a false-positive
    ``FLAG FOUND`` event because the agent's summary prose included
    ``FLAG{...}`` as a structural placeholder. Each rejection here is
    motivated by a real false-positive observed in the sweep; the
    rejection rules are also small enough to not impact any real XBOW
    flag (real flags are 64-char SHA-256 hex bodies).
    """

    def test_dot_ellipsis_placeholder_rejected(self):
        # Exact false positive from  sweep — XBEN-010, 030, 066 all hit.
        det = FlagDetector()
        text = "\nI couldn't extract a live flag from the target.\n\nFLAG{...}"
        assert det.scan(text) == []

    def test_question_mark_placeholder_rejected(self):
        det = FlagDetector()
        assert det.scan("FLAG{?}") == []

    def test_angle_bracket_placeholder_rejected(self):
        # Short angle-bracket placeholders are caught by the alnum floor.
        # Long-form placeholder prose (``flag{<the actual flag value here>}``)
        # is intentionally NOT rejected — the body is indistinguishable from
        # a legitimate flag without semantic understanding, and rejecting on
        # an English-word denylist risks missing real phrase-form flags like
        # XBEN-061's ``flag{I'm_a_Script_Kiddie}``.
        det = FlagDetector()
        assert det.scan("the flag would be FLAG{<flag>}") == []

    def test_short_alpha_placeholder_rejected(self):
        # ``flag{TBD}`` (3 chars) and ``flag{x}`` (1 char) are too short.
        det = FlagDetector()
        assert det.scan("flag{TBD}") == []
        assert det.scan("flag{x}") == []
        assert det.scan("flag{abc}") == []  # 3 chars, all alnum but too short

    def test_punctuation_only_body_rejected(self):
        # 8+ chars body but no alphanumerics — still placeholder-shaped.
        det = FlagDetector()
        assert det.scan("FLAG{........}") == []
        assert det.scan("FLAG{<------>}") == []
        assert det.scan("FLAG{////////}") == []

    def test_three_alnum_body_rejected(self):
        # 8-char body but only 3 alnums — below the 4-alnum floor.
        det = FlagDetector()
        assert det.scan("FLAG{a.b.c...}") == []  # 8 chars, 3 alnum

    def test_real_xbow_64hex_accepted(self):
        # Sanity: every real XBOW flag (64-char SHA-256 hex) must still match.
        det = FlagDetector()
        flag = "FLAG{016fbb671566e953b8cb08ffc01bb330002615f78ec3e6cc8438085b476834eb}"
        assert det.scan(f"agent prose ... {flag} ... more prose") == [flag]

    def test_minimum_acceptable_body_at_boundary(self):
        # Inner length 8, all alnum — should accept (real CTFs use 8-char
        # alnum flags occasionally; the floor is conservative).
        det = FlagDetector()
        assert det.scan("flag{abcd1234}") == ["flag{abcd1234}"]

    def test_mixed_real_and_placeholder_returns_only_real(self):
        # Realistic LLM output: prose with placeholder + later a real flag.
        det = FlagDetector()
        text = (
            "I expected to receive FLAG{...} but the response was 404.\n"
            "Then on the second attempt I got: "
            "FLAG{016fbb671566e953b8cb08ffc01bb330002615f78ec3e6cc8438085b476834eb}"
        )
        out = det.scan(text)
        assert out == [
            "FLAG{016fbb671566e953b8cb08ffc01bb330002615f78ec3e6cc8438085b476834eb}"
        ]
