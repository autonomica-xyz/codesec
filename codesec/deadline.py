"""Absolute deadline plumbing (P05).

One common absolute deadline is passed to every stage, call, repair, retry
and tool. All timing uses the monotonic clock. Semantics:

- ``closing``: elapsed >= 80% of the total budget (synthesis reserve
  fraction 0.20) — stop admitting new Hunt/Gapfill/Feedback breadth work.
- ``exhausted``: remaining time <= FINAL_SNAPSHOT_RESERVE_S (30 s) — all
  model work must stop; only the deterministic snapshot/export may run.
- Request/socket/tool timeouts are bounded by the remaining time; backoff
  sleeps are clamped so they never cross the deadline, and no request is
  restarted after budget exhaustion.
"""

from __future__ import annotations

import asyncio
import time

SYNTHESIS_RESERVE_FRACTION = 0.20
FINAL_SNAPSHOT_RESERVE_S = 30.0
#: Extra cleanup grace reported separately by the outer supervisor.
OUTER_CLEANUP_GRACE_S = 30.0


class TimeBudgetExceeded(RuntimeError):
    """Wall-clock budget exhausted (P05)."""


class Deadline:
    """Monotonic absolute deadline shared by all stages of one run."""

    def __init__(self, total_seconds: float, *, clock=time.monotonic):
        if total_seconds <= 0:
            raise ValueError("total_seconds must be positive")
        self.clock = clock
        self.total = float(total_seconds)
        self.start = self.clock()

    # ---- state ----------------------------------------------------------

    def elapsed(self) -> float:
        return self.clock() - self.start

    def remaining(self) -> float:
        return self.total - self.elapsed()

    def closing(self) -> bool:
        """Elapsed >= 80% of the budget: synthesis reserve entered."""
        return self.elapsed() >= (1.0 - SYNTHESIS_RESERVE_FRACTION) * self.total

    def exhausted(self) -> bool:
        """Remaining <= the 30 s final-snapshot reserve: model work stops."""
        return self.remaining() <= FINAL_SNAPSHOT_RESERVE_S

    # ---- gating ---------------------------------------------------------

    def check(self, what: str) -> None:
        """Raise TimeBudgetExceeded when the budget (minus the snapshot
        reserve) is spent."""
        if self.exhausted():
            raise TimeBudgetExceeded(
                f"time budget exhausted before {what}: "
                f"{self.elapsed():.1f}s elapsed of {self.total:.1f}s "
                f"(remaining {self.remaining():.1f}s <= "
                f"{FINAL_SNAPSHOT_RESERVE_S:.0f}s snapshot reserve)"
            )

    def check_closing(self, what: str) -> None:
        """Raise when new breadth work must no longer be admitted."""
        self.check(what)
        if self.closing():
            raise TimeBudgetExceeded(
                f"closing mode (>= {int((1.0 - SYNTHESIS_RESERVE_FRACTION) * 100)}% "
                f"of budget elapsed) — no new breadth work: {what}"
            )

    # ---- bounding I/O ---------------------------------------------------

    def request_timeout(self, default: float) -> float:
        """Socket/request timeout bounded by the remaining time (always
        positive and finite so a hung peer cannot outlive the budget)."""
        remaining = self.remaining()
        if remaining <= 0:
            return 0.001
        return max(0.001, min(default, remaining + FINAL_SNAPSHOT_RESERVE_S))

    def clamp_sleep(self, seconds: float) -> float:
        """Backoff sleep clamped to the remaining time — never sleeps past
        the deadline."""
        return max(0.0, min(seconds, self.remaining()))

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(self.clamp_sleep(seconds))
        if self.exhausted():
            raise TimeBudgetExceeded(
                "backoff sleep reached the budget; not restarting the request"
            )

    # ---- plumbing -------------------------------------------------------

    def absolute(self) -> float:
        """Monotonic timestamp at which the full budget is spent."""
        return self.start + self.total

    def snapshot_deadline(self) -> float:
        """Monotonic timestamp at which model work must have stopped."""
        return self.absolute() - FINAL_SNAPSHOT_RESERVE_S
