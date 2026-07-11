"""Deadline — pause-aware wall-clock budget.

Tracks elapsed wall time against a configurable maximum, with the
ability to *pause* the clock during operations that don't count against
the budget (e.g. rate-limit backoff sleep). Modelled on BoxPwnr's
deadline pattern.

Usage::

    deadline = Deadline(max_seconds=600)
    while not deadline.expired:
        do_work()
        with deadline.pause():
            time.sleep(rate_limit_wait)  # excluded from budget

A `max_seconds` of `None` disables the deadline entirely (`expired`
is always False, `remaining` is `None`).
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Iterator


class Deadline:
    """Pause-aware wall-clock deadline."""

    def __init__(self, max_seconds: float | None = None) -> None:
        self._max = max_seconds
        self._start = time.monotonic()
        self._paused_total = 0.0
        self._pause_started: float | None = None

    @property
    def max_seconds(self) -> float | None:
        return self._max

    @property
    def elapsed(self) -> float:
        """Wall-clock seconds spent that *count* toward the budget."""
        raw = time.monotonic() - self._start
        if self._pause_started is not None:
            # Currently paused — exclude the in-flight pause too.
            current_pause = time.monotonic() - self._pause_started
            return raw - self._paused_total - current_pause
        return raw - self._paused_total

    @property
    def remaining(self) -> float | None:
        """Seconds left in the budget, or `None` if unbounded.

        Never returns a negative number — clamps at 0.
        """
        if self._max is None:
            return None
        return max(0.0, self._max - self.elapsed)

    @property
    def expired(self) -> bool:
        if self._max is None:
            return False
        return self.elapsed >= self._max

    def pause(self) -> "_PauseCtx":
        """Context manager that excludes its body from the budget.

        Re-entrant on the same Deadline is NOT supported — nested
        `with deadline.pause():` blocks will trigger a `RuntimeError`
        to surface bugs early.
        """
        return _PauseCtx(self)


class _PauseCtx:
    def __init__(self, deadline: Deadline) -> None:
        self._d = deadline

    def __enter__(self) -> Deadline:
        if self._d._pause_started is not None:
            raise RuntimeError("Deadline.pause() is not re-entrant")
        self._d._pause_started = time.monotonic()
        return self._d

    def __exit__(self, *exc: object) -> None:
        if self._d._pause_started is None:
            return
        self._d._paused_total += time.monotonic() - self._d._pause_started
        self._d._pause_started = None


@contextmanager
def no_deadline() -> Iterator[Deadline]:
    """A null-object Deadline that never expires — useful for tests."""
    yield Deadline(max_seconds=None)
