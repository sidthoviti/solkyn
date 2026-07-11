""" Tests for the exit-reason vocabulary validator."""

from __future__ import annotations

import pytest

from solkyn.agents.exit_reasons import (
    EXIT_REASONS,
    InvalidExitReasonError,
    validate_exit_reason,
)


class TestExitReasonsVocabulary:
    def test_known_reasons_pass_through(self):
        for reason in EXIT_REASONS:
            assert validate_exit_reason(reason) == reason

    def test_none_coerces_to_error(self):
        assert validate_exit_reason(None) == "error"
        assert validate_exit_reason(None, strict=False) == "error"

    def test_unknown_reason_strict_raises(self):
        with pytest.raises(InvalidExitReasonError):
            validate_exit_reason("refusal")

    def test_unknown_reason_lenient_coerces_to_error(self, caplog):
        assert validate_exit_reason("refusal", strict=False) == "error"

    def test_vocabulary_is_locked(self):
        # If you add a new exit_reason, update both this set AND the
        # the solver architecture notes
        assert EXIT_REASONS == frozenset({
            "flag_found",
            "max_iterations",
            "no_tool_calls",
            "time_limit",
            "cost_limit",
            "error",
        })
