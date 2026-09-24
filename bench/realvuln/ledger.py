#!/usr/bin/env python3
"""Append-only, locked, experiment-scoped attempt ledger (P07).

Replaces the old shared ``failed-trials.txt`` (copied and truncated across
waves, unscoped by tag/model/experiment). Every event carries the
experiment id, opaque ids, timestamps, the configuration hash, status,
reason code, exit status, artifact hashes and the attempt-selection reason.
The ledger is never truncated; each experiment gets its own file under
``<exp>/operator/attempts.jsonl``.

Locking: an exclusive ``fcntl`` lock on the sidecar ``.lock`` file guards
appends so two controllers cannot interleave (double-commit is additionally
prevented by completion markers, which are created atomically). Claiming a
cell for execution uses BOTH a per-cell flock (``cell_lock`` — held for the
whole attempt so two controllers never run one cell concurrently) and a
ledger ``cell_claim`` record, refused when the cell is already accounted or
an attempt is still open.

Attempt-selection rule (frozen): the FIRST inference-bearing attempt is the
operational primary — including a ``failed_no_output`` end. Resume never
replaces it. A pre-inference (setup) failure may be retried at most once;
a missing or inconsistent ``made_inference_requests`` mark makes the cell
invalid, not freely retryable.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import time
import uuid
from pathlib import Path

TERMINAL_STATUSES = frozenset({
    "completed",          # attempt produced committed outputs
    "failed_output",      # terminal run failure with output produced anyway
    "failed_no_output",   # terminal run failure without output
    "setup_failed",       # pre-inference setup failure (retry-eligible once)
    "invalidated",        # protocol breach / config mismatch
})

#: Statuses that may consume the single setup retry: the attempt ended
#: before inference, so the run's primary slot is still unfilled.
SETUP_RETRY_MAX = 1


class LedgerConflictError(RuntimeError):
    """Another controller already holds the ledger or the state conflicts."""


class AttemptLedger:
    def __init__(self, path: Path, *, experiment_id: str, config_hash: str):
        self.path = Path(path)
        self.experiment_id = experiment_id
        self.config_hash = config_hash
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock_path = self.path.with_suffix(".jsonl.lock")
        self._lock_path.touch(exist_ok=True)

    # ---- append ----------------------------------------------------------

    def append(self, event: dict) -> dict:
        record = {
            "ledger_id": uuid.uuid4().hex,
            "experiment_id": self.experiment_id,
            "config_hash": self.config_hash,
            "ts": time.time(),
            **event,
        }
        with self._lock_path.open("r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                for existing in self._iter_records():
                    self._check_conflicts(existing, record)
                with self.path.open("a") as fh:
                    fh.write(json.dumps(record, ensure_ascii=False) + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)
        return record

    def _check_conflicts(self, existing: dict, new: dict) -> None:
        if (
            existing.get("type") == "attempt_end"
            and existing.get("cell_id") == new.get("cell_id")
            and existing.get("attempt_id") == new.get("attempt_id")
            and new.get("type") == "attempt_end"
        ):
            raise LedgerConflictError(
                f"attempt {new.get('attempt_id')} already has a terminal "
                "record — never rewrite ledger history"
            )
        if (
            existing.get("config_hash")
            and new.get("config_hash")
            and existing["config_hash"] != new["config_hash"]
            and existing.get("experiment_id") == new.get("experiment_id")
        ):
            raise LedgerConflictError(
                "ledger events for one experiment must share one "
                f"configuration hash ({existing['config_hash']} vs "
                f"{new['config_hash']})"
            )

    # ---- read ------------------------------------------------------------

    def _iter_records(self):
        if not self.path.exists():
            return
        with self.path.open() as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def records(self, cell_id: str | None = None) -> list[dict]:
        return [
            r for r in self._iter_records()
            if cell_id is None or r.get("cell_id") == cell_id
        ]

    def attempts(self, cell_id: str) -> list[dict]:
        started = {
            r["attempt_id"]: r
            for r in self.records(cell_id)
            if r.get("type") == "attempt_start"
        }
        out = []
        for r in self.records(cell_id):
            if r.get("type") == "attempt_end":
                attempt = dict(started.get(r["attempt_id"], {}))
                attempt.update(r)
                out.append(attempt)
        return out

    def open_attempts(self, cell_id: str) -> list[str]:
        """Attempt ids with an attempt_start but no attempt_end — either
        in-flight under another controller or interrupted by a crash."""
        started = {
            r["attempt_id"]
            for r in self.records(cell_id)
            if r.get("type") == "attempt_start"
        }
        ended = {
            r["attempt_id"]
            for r in self.records(cell_id)
            if r.get("type") == "attempt_end"
        }
        return sorted(started - ended)

    def terminal_state(self, cell_id: str) -> dict | None:
        """Terminal state of the cell: the first inference-bearing attempt's
        end record wins (operational primary — a failed_no_output end after
        inference is still primary), else the last terminal record."""
        ends = [r for r in self.records(cell_id)
                if r.get("type") == "attempt_end"]
        if not ends:
            return None
        for end in ends:
            if end.get("made_inference_requests") is True:
                if end.get("status") == "setup_failed":
                    # A setup failure cannot have made inference — the
                    # attribution contradicts itself; surface it, never
                    # silently accept.
                    return dict(end, attribution_inconsistent=True)
                return end
        state = dict(ends[-1])
        if state.get("made_inference_requests") is None:
            # No explicit inference mark: attribution is missing, so the
            # cell's validity cannot be established from the ledger alone.
            state["attribution_inconsistent"] = True
        return state

    def cell_accounted(self, cell_id: str) -> bool:
        state = self.terminal_state(cell_id)
        return state is not None and state.get("status") in TERMINAL_STATUSES

    # ---- claiming ---------------------------------------------------------

    def cell_lock_path(self, cell_id: str) -> Path:
        locks = self.path.parent / "cell-locks"
        locks.mkdir(parents=True, exist_ok=True)
        return locks / f"{cell_id}.lock"

    @contextlib.contextmanager
    def cell_lock(self, cell_id: str):
        """Exclusive non-blocking cell lock held for a whole attempt — two
        controllers can never execute the same cell concurrently."""
        path = self.cell_lock_path(cell_id)
        fh = path.open("a+")
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            fh.close()
            raise LedgerConflictError(
                f"cell {cell_id} is locked by another controller"
            ) from error
        try:
            yield
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)
            fh.close()

    def reconcile_interrupted(
        self,
        cell_id: str,
        *,
        made_inference,
    ) -> list[str]:
        """Close open attempts (attempt_start without attempt_end) left by
        an interrupted controller. ``made_inference(attempt_id)`` consults
        trusted request records: an interrupted inference-bearing attempt is
        a terminal operational failure; a pre-inference interruption is a
        setup failure that may consume the one setup retry."""
        closed: list[str] = []
        for attempt_id in self.open_attempts(cell_id):
            inferred = made_inference(attempt_id)
            self.append({
                "type": "attempt_end",
                "cell_id": cell_id,
                "attempt_id": attempt_id,
                "status": (
                    "failed_no_output" if inferred is True
                    else "setup_failed"
                ),
                "reason_code": "controller_interrupted",
                "exit_status": None,
                # None stays None: missing attribution is flagged
                # inconsistent by terminal_state, never silently False.
                "made_inference_requests": inferred,
                "attempt_selection": "interrupted_attempt_closed",
            })
            closed.append(attempt_id)
        return closed

    def claim_cell(self, cell_id: str, attempt_id: str) -> dict:
        """Claim a cell for one new attempt under the append lock.

        Refused (LedgerConflictError) when:
        - an open attempt exists (reconcile_interrupted first),
        - a terminal inference-bearing attempt exists (primary is fixed), or
        - the single setup retry is already spent (>= 1 + SETUP_RETRY_MAX
          attempts).
        """
        with self._lock_path.open("r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                records = list(self._iter_records())
                starts = [r for r in records
                          if r.get("type") == "attempt_start"
                          and r.get("cell_id") == cell_id]
                ends = [r for r in records
                        if r.get("type") == "attempt_end"
                        and r.get("cell_id") == cell_id]
                ended_ids = {r["attempt_id"] for r in ends}
                open_ids = [r["attempt_id"] for r in starts
                            if r["attempt_id"] not in ended_ids]
                if open_ids:
                    raise LedgerConflictError(
                        f"cell {cell_id} has open attempts {open_ids} — "
                        "reconcile interrupted attempts before claiming"
                    )
                inference_ends = [
                    r for r in ends if r.get("made_inference_requests") is True
                ]
                if inference_ends:
                    raise LedgerConflictError(
                        f"cell {cell_id} already has an inference-bearing "
                        f"terminal attempt ({inference_ends[0]['attempt_id']})"
                        " — the operational primary is fixed"
                    )
                if any(r.get("status") == "invalidated" for r in ends):
                    raise LedgerConflictError(
                        f"cell {cell_id} is invalidated — never retried"
                    )
                if any(
                    r.get("made_inference_requests") is None for r in ends
                ):
                    raise LedgerConflictError(
                        f"cell {cell_id} has an attempt with unknown "
                        "inference attribution — the cell is invalidated, "
                        "never retried (a retry could produce a second "
                        "inference-bearing attempt)"
                    )
                if len(ends) > SETUP_RETRY_MAX:
                    raise LedgerConflictError(
                        f"cell {cell_id} exhausted its setup retry "
                        f"({len(ends)} pre-inference attempts)"
                    )
                record = {
                    "ledger_id": uuid.uuid4().hex,
                    "experiment_id": self.experiment_id,
                    "config_hash": self.config_hash,
                    "ts": time.time(),
                    "type": "cell_claim",
                    "cell_id": cell_id,
                    "attempt_id": attempt_id,
                }
                with self.path.open("a") as fh:
                    fh.write(json.dumps(record, ensure_ascii=False) + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
                return record
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)
