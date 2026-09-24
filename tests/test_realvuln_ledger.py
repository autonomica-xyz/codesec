"""P07 attempt-ledger behavior tests."""

from __future__ import annotations

import json

import pytest

from bench.realvuln.ledger import (
    AttemptLedger,
    LedgerConflictError,
)


def _ledger(tmp_path, experiment_id="exp-1", config_hash="cfg-aaa"):
    return AttemptLedger(
        tmp_path / "attempts.jsonl",
        experiment_id=experiment_id,
        config_hash=config_hash,
    )


def test_append_only_never_truncates(tmp_path):
    ledger = _ledger(tmp_path)
    for i in range(5):
        ledger.append({"type": "note", "n": i})
    ledger.append({"type": "attempt_end", "cell_id": "c1", "attempt_id": "a1",
                   "status": "completed"})
    # A second controller instance sees the full history.
    other = _ledger(tmp_path)
    assert len(other.records()) == 6
    # Appending more never removes the earlier terminal record.
    other.append({"type": "note", "n": 99})
    assert len(other.records()) == 7


def test_terminal_attempt_cannot_be_rewritten(tmp_path):
    ledger = _ledger(tmp_path)
    ledger.append({"type": "attempt_start", "cell_id": "c1",
                   "attempt_id": "a1"})
    ledger.append({"type": "attempt_end", "cell_id": "c1", "attempt_id": "a1",
                   "status": "completed"})
    with pytest.raises(LedgerConflictError, match="never rewrite"):
        ledger.append({"type": "attempt_end", "cell_id": "c1",
                       "attempt_id": "a1", "status": "failed_no_output"})


def test_config_hash_scope_is_enforced(tmp_path):
    ledger = _ledger(tmp_path, config_hash="cfg-aaa")
    ledger.append({"type": "note"})
    with pytest.raises(LedgerConflictError, match="one configuration hash"):
        ledger.append({"type": "note", "config_hash": "cfg-bbb"})


def test_first_inference_bearing_attempt_is_operational_primary(tmp_path):
    ledger = _ledger(tmp_path)
    ledger.append({"type": "attempt_start", "cell_id": "c1",
                   "attempt_id": "a1"})
    ledger.append({"type": "attempt_end", "cell_id": "c1", "attempt_id": "a1",
                   "status": "failed_output",
                   "made_inference_requests": True})
    # A later diagnostic rerun succeeds but cannot replace the primary.
    ledger.append({"type": "attempt_start", "cell_id": "c1",
                   "attempt_id": "a2"})
    ledger.append({"type": "attempt_end", "cell_id": "c1", "attempt_id": "a2",
                   "status": "completed", "made_inference_requests": True})

    state = ledger.terminal_state("c1")
    assert state["attempt_id"] == "a1"
    assert state["status"] == "failed_output"
    assert ledger.cell_accounted("c1")


def test_setup_failure_without_inference_is_not_primary(tmp_path):
    ledger = _ledger(tmp_path)
    ledger.append({"type": "attempt_start", "cell_id": "c2",
                   "attempt_id": "a1"})
    ledger.append({"type": "attempt_end", "cell_id": "c2", "attempt_id": "a1",
                   "status": "setup_failed", "made_inference_requests": False})
    ledger.append({"type": "attempt_start", "cell_id": "c2",
                   "attempt_id": "a2"})
    ledger.append({"type": "attempt_end", "cell_id": "c2", "attempt_id": "a2",
                   "status": "completed", "made_inference_requests": True})

    state = ledger.terminal_state("c2")
    assert state["attempt_id"] == "a2", (
        "pre-inference setup failures leave the primary to the real attempt"
    )


def test_unaccounted_cell_has_no_terminal_state(tmp_path):
    ledger = _ledger(tmp_path)
    ledger.append({"type": "attempt_start", "cell_id": "c3",
                   "attempt_id": "a1"})
    assert ledger.terminal_state("c3") is None
    assert not ledger.cell_accounted("c3")


def test_two_controllers_cannot_interleave_terminal_states(tmp_path):
    import threading
    ledger = _ledger(tmp_path)
    conflicts = []

    def writer(name: str):
        try:
            for i in range(20):
                ledger.append({
                    "type": "attempt_end",
                    "cell_id": f"c-{name}", "attempt_id": f"a-{name}-{i}",
                    "status": "completed",
                })
        except LedgerConflictError as error:
            conflicts.append(str(error))

    threads = [threading.Thread(target=writer, args=(n,)) for n in "ab"]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not conflicts
    records = ledger.records()
    assert len(records) == 40
    # every line parses as complete JSON (no interleaved partial writes)
    for line in (tmp_path / "attempts.jsonl").read_text().splitlines():
        json.loads(line)
