""" `resolve_max_iter` helper for per-difficulty iteration overrides.

Verifies that the ``--max-iterations-l3`` CLI flag in ``scripts/run_challenges.py``
applies its override only to challenges whose level resolves to 3, and falls
back to the default cap for everything else (including the unparseable
sentinel ``"?"`` used when the inventory JSON has no level field).
"""

from __future__ import annotations

import sys
from pathlib import Path

# Mirror scripts/run_challenges.py's sys.path hack so we can import it as a
# module despite it living outside the package tree.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

# Importing the script triggers a top-level argparse setup only inside main(),
# so a bare import is safe.
from run_challenges import resolve_max_iter  # noqa: E402


class TestResolveMaxIter:
    def test_no_override_returns_default(self):
        assert resolve_max_iter("3", default=25, l3_override=None) == 25
        assert resolve_max_iter("1", default=25, l3_override=None) == 25
        assert resolve_max_iter("?", default=25, l3_override=None) == 25

    def test_override_applies_only_to_level_3(self):
        assert resolve_max_iter("3", default=25, l3_override=50) == 50
        assert resolve_max_iter("2", default=25, l3_override=50) == 25
        assert resolve_max_iter("1", default=25, l3_override=50) == 25

    def test_override_handles_whitespace_in_level(self):
        # Inventory JSON occasionally has padded strings; the helper strips.
        assert resolve_max_iter(" 3 ", default=25, l3_override=50) == 50
        assert resolve_max_iter("\t3\n", default=25, l3_override=50) == 50

    def test_override_does_not_apply_to_unknown_level(self):
        assert resolve_max_iter("?", default=25, l3_override=50) == 25
        assert resolve_max_iter("", default=25, l3_override=50) == 25

    def test_override_smaller_than_default_still_applied_for_l3(self):
        # The helper does not enforce override > default — the operator is
        # responsible for choosing a sensible value. Documented behaviour.
        assert resolve_max_iter("3", default=50, l3_override=25) == 25
