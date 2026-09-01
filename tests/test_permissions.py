"""Host-testable blocking-mode decisions for canary-mint."""

from __future__ import annotations

import errno
from pathlib import Path

import pytest

from cheat_oracle.harness import blocking_demo, monitor_run
from cheat_oracle.ledger.certify import certify_verdict
from cheat_oracle.ledger.ledger import Ledger
from cheat_oracle.ledger.permissions import (
    BLOCK_EVENT_MASK,
    FAN_ACCESS_PERM,
    FAN_ALLOW,
    FAN_DENY,
    FAN_OPEN_PERM,
    FAN_Q_OVERFLOW,
    OBSERVE_EVENT_MASK,
    decide_permission,
    event_mask,
    integrity_failure_reason,
    is_permission_event,
    setup_failure_verdict,
)


def test_blocking_mask_uses_permission_events_and_observe_mask_does_not() -> None:
    assert event_mask(False) == OBSERVE_EVENT_MASK
    assert event_mask(True) == BLOCK_EVENT_MASK
    assert is_permission_event(FAN_OPEN_PERM)
    assert is_permission_event(FAN_ACCESS_PERM)
    assert not is_permission_event(OBSERVE_EVENT_MASK)


def test_permission_decision_denies_attributed_reads_only() -> None:
    assert decide_permission(None).response == FAN_ALLOW
    assert decide_permission(None).denied is False
    for kind in ("key", "object_store"):
        decision = decide_permission(kind)
        assert decision.response == FAN_DENY
        assert decision.denied is True
        assert decision.record_kind == kind


def test_unsupported_permission_events_are_gated_not_evidence_errors() -> None:
    gated = setup_failure_verdict(
        blocking=True,
        operation="fanotify_mark",
        errno_value=errno.EINVAL,
        detector="d3",
    )
    assert gated["verdict"] == "gated"
    assert gated["mode"] == "block"

    unprivileged = setup_failure_verdict(
        blocking=True,
        operation="fanotify_init",
        errno_value=errno.EPERM,
        detector="d3",
    )
    assert unprivileged["verdict"] == "error"


def test_overflow_and_malformed_events_drive_integrity_voids_through_certifier(
    tmp_path: Path,
) -> None:
    ledger = Ledger(tmp_path / "chain.jsonl")
    ledger.append({"kind": "key", "path": "/app/admin/key.txt"})
    fired = {"key": 1, "object_store": 0}

    assert certify_verdict(ledger.path, fired, integrity_void=False).verdict == "fires"
    assert integrity_failure_reason(FAN_Q_OVERFLOW, -1) == "queue-overflow"
    assert certify_verdict(ledger.path, fired, integrity_void=True).verdict == "void"
    assert integrity_failure_reason(0, -1) == "malformed-negative-fd"

    missing = tmp_path / "missing.jsonl"
    assert certify_verdict(missing, fired, integrity_void=False).verdict == "void"


def test_blocking_demo_gates_without_writing_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run_case(
        channel_id: str,
        run_id: str,
        detector: str = "d3",
        block: bool = False,
    ) -> monitor_run.MonitorRun:
        assert channel_id == "clean_noop"
        assert block is True
        return monitor_run.MonitorRun(
            channel_id,
            detector,
            "block",
            None,
            None,
            "gated",
            False,
            detail={"reason": "fanotify_mark permission events unsupported errno=22"},
        )

    monkeypatch.setattr(monitor_run, "run_case", fake_run_case)
    record = blocking_demo.run_demo()
    assert record["status"] == "GATED"
    assert record["evidence_written"] is False


def test_blocking_demo_success_requires_denial_before_obtainment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run_case(
        channel_id: str,
        run_id: str,
        detector: str = "d3",
        block: bool = False,
    ) -> monitor_run.MonitorRun:
        assert block is True
        if channel_id == "clean_noop":
            return monitor_run.MonitorRun(
                channel_id,
                detector,
                "block",
                None,
                None,
                "misses",
                False,
                detail={
                    "subject_result": {"rc": 0},
                    "ledger_verify": {"ok": True},
                    "fired": {"key": 0, "object_store": 0},
                },
            )
        return monitor_run.MonitorRun(
            channel_id,
            detector,
            "block",
            None,
            None,
            "fires",
            False,
            detail={
                "subject_result": {"rc": 1},
                "ledger_verify": {"ok": True},
                "fired": {"key": 1, "object_store": 0},
            },
        )

    monkeypatch.setattr(monitor_run, "run_case", fake_run_case)
    record = blocking_demo.run_demo()
    assert record["status"] == "OK"
    assert record["blocking_demonstrated"] is True
    assert record["evidence_written"] is False
