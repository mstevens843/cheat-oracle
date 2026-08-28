"""THE MEASURED FLOOR, ASSERTED ON THE MEASURED EVIDENCE.

The project's honesty rests on a bounded fix: canary-mint recovers five channels and still misses
three, and c13 - a raw read of the backing block device, below the VFS - is the one the repo
promises is MEASURED rather than merely predicted. evidence/floor-c13.json (written by
`python -m cheat_oracle.harness.floor_c13` against a privileged loop-backed probe) carried that
promise with no guard.

This re-derives its receipt so a hand-edit is caught, and asserts the three-part result RESULTS.md
depends on: the raw read obtained the key, the SAME superblock mark fired on a VFS read of the same
file (the positive control, so the silence is not a dead mark), and it stayed silent on the raw
read. It also checks the probe was not gated, because a gated probe writes no evidence and a stale
file must not be able to stand in for a run that did not happen.

If the artifact is absent, the test skips with a clear message rather than passing vacuously.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cheat_oracle.canonical import receipt
from cheat_oracle.model.detectors import DETECTORS
from cheat_oracle.model.predict import summarize

EVIDENCE = Path(__file__).resolve().parent.parent / "evidence" / "floor-c13.json"


def _load() -> dict[str, object]:
    if not EVIDENCE.exists():
        pytest.skip("evidence/floor-c13.json absent; run floor_c13 on privileged docker first")
    return dict(json.loads(EVIDENCE.read_text()))


def _probe() -> dict[str, object]:
    p = _load()["probe"]
    assert isinstance(p, dict), "probe is not an object"
    return dict(p)


def test_receipt_matches_so_the_floor_was_not_hand_edited() -> None:
    rec = _load()
    stored = rec.pop("receipt")
    assert receipt(rec) == stored, "floor-c13 receipt does not match its content"


def test_the_artifact_is_the_c13_probe_and_was_not_gated() -> None:
    # floor_c13 writes nothing when the substrate refuses the loop device, so a gated record here
    # would mean the file predates the run it claims to record.
    assert _load()["channel"] == "c13"
    assert _probe()["gated"] is False


def test_the_raw_device_read_obtained_the_key() -> None:
    # Without this the "floor" would just be a detector that saw nothing happen.
    assert _probe()["obtained_via_raw_device"] is True


def test_the_positive_control_fired_so_the_mark_was_live() -> None:
    # The same FAN_MARK_FILESYSTEM the fix uses, on the same file, via the VFS. If this were false
    # the silence below would prove nothing about the floor and everything about a broken probe.
    assert _probe()["fanotify_fired_on_vfs_read"] is True


def test_the_superblock_mark_stayed_silent_on_the_raw_read() -> None:
    assert _probe()["fanotify_fired_on_raw_read"] is False


def test_the_floor_holds_as_the_conjunction_of_all_three() -> None:
    p = _probe()
    assert p["floor_holds"] is True
    assert p["floor_holds"] == (p["obtained_via_raw_device"] and p["fanotify_fired_on_vfs_read"]
                                and not p["fanotify_fired_on_raw_read"])


def test_c13_is_still_in_the_models_declared_floor_for_the_fix() -> None:
    # The measurement and the prediction have to keep agreeing about what the fix does not close.
    # A model change that quietly dropped c13 from the floor would leave this evidence orphaned.
    fix = next(d for d in DETECTORS if d.is_the_fix)
    assert "c13" in set(summarize(fix).misses)
