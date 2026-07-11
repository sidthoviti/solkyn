"""Flag detector — scan text for flag patterns.

Default patterns intentionally permissive: real CTF/XBOW flags are
``flag{<arbitrary text>}``. The historical ``[a-fA-F0-9]+`` pattern
rejected EVERY real XBOW flag (which use UUIDs with hyphens or English
phrases), causing silent auto-detection failures on tool outputs that
literally contained the flag. See development-log entry "Phase 7 — flag
detector regex fix" for the bug analysis.

Allowed inside the braces: any printable non-`}` character that is
plausible in a flag — alphanumerics, underscores, hyphens, dots, colons,
slashes, equals signs, plus signs (base64 padding), apostrophes,
spaces. We exclude ``\n`` and ``}`` so the match terminates cleanly.

 placeholder filter — after the regex matches, we discard
"placeholder-shaped" candidates that the LLM commonly emits in summary
prose (``FLAG{...}``, ``FLAG{<the flag>}``, ``flag{TBD}``,
``flag{REPLACEME}``). The  L3 sweep showed all 3 challenges fail
with a false-positive ``FLAG FOUND`` event because the agent's prose
included ``FLAG{...}`` as a structural placeholder. We require the
inner content to be at least ``_MIN_INNER_LEN`` chars AND contain at
least ``_MIN_ALNUM`` alphanumeric characters. Real XBOW flags are
64-char SHA-256 hex bodies, so an 8-char / 4-alnum floor is generous
to non-XBOW CTF formats while still excluding every placeholder shape
observed in the  sweep.
"""

from __future__ import annotations

import re

# Default flag patterns. Order matters: the more specific (uppercase
# ``FLAG``) is listed first so a mixed-case ``Flag{..}`` still matches via
# case-insensitive fallback if needed.
DEFAULT_PATTERNS = [
    # Standard XBOW / CTF format. Body = anything except `}` and newline.
    # Anchored on `flag{` (case-insensitive) for both prefixes.
    r"(?:FLAG|flag)\{[^}\n]{1,256}\}",
]

#  placeholder-rejection thresholds. Documented above; do not
# tighten without measuring impact on real XBOW solves first (the regex
# is hot-path: every LLM response and tool output is scanned).
_MIN_INNER_LEN = 8
_MIN_ALNUM = 4
_BRACE_BODY_RE = re.compile(r"\{([^}\n]+)\}")


def _looks_like_placeholder(match_str: str) -> bool:
    """Return True when ``match_str`` looks like an LLM-emitted placeholder
    rather than a real flag.

    Triggers (only applied when the match has a ``{body}`` shape):
      * Inner content shorter than ``_MIN_INNER_LEN`` (8) chars — real
        XBOW flags are 64-char hex; 8 is a safety margin for shorter
        third-party CTF formats.
      * Inner content has fewer than ``_MIN_ALNUM`` (4) alphanumeric
        characters — kills ``FLAG{...}``, ``FLAG{<x>}``, ``FLAG{?}``.

    Custom user-supplied patterns without a ``{body}`` shape are always
    accepted (we have no body to inspect, and the user opted into
    whatever shape they configured).

    We do NOT try to enumerate placeholder words (``TBD``, ``REPLACEME``,
    etc.) because those would require an open-ended denylist and risk
    rejecting legitimate flags. The two rules above cover every false
    positive observed in the  sweep without changing behaviour for
    any flag in the XBOW corpus.
    """
    body_match = _BRACE_BODY_RE.search(match_str)
    if not body_match:
        # No ``{...}`` shape — must be a custom pattern; accept as-is.
        return False
    body = body_match.group(1)
    if len(body) < _MIN_INNER_LEN:
        return True
    alnum_count = sum(1 for c in body if c.isalnum())
    if alnum_count < _MIN_ALNUM:
        return True
    return False


class FlagDetector:
    """Scan text for flag patterns."""

    def __init__(self, patterns: list[str] | None = None):
        raw = patterns or DEFAULT_PATTERNS
        self._patterns = [re.compile(p) for p in raw]

    def scan(self, text: str) -> list[str]:
        """Find all flag occurrences in text.

        Returns deduplicated list of matched flags. Placeholder-shaped
        matches (see ``_looks_like_placeholder``) are dropped silently.
        """
        found: list[str] = []
        seen: set[str] = set()
        for pattern in self._patterns:
            for match in pattern.finditer(text):
                flag = match.group(0)
                if flag in seen:
                    continue
                if _looks_like_placeholder(flag):
                    continue
                found.append(flag)
                seen.add(flag)
        return found

