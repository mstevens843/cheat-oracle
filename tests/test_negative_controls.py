"""The false-positive floor, asserted on measured evidence. A detector that catches 7 of 12 hacks is
only trustworthy if it does not also fire on benign work; NEGATIVE_CONTROL_SUBJECT (clean_noop) does
legitimate work that never reads the key, and every detector must score it clean.

Reads evidence/negative-control.json (written by `python -m cheat_oracle.harness.negative_control`
against real containers), re-derives its receipt so a hand-edit is caught, and requires that no
detector fired. Skips with a clear message if the artifact is absent, so a green run can never mean
"never measured".
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cheat_oracle.canonical import receipt

EVIDENCE = Path(__file__).resolve().parent.parent / "evidence" / "negative-control.json"


def _load() -> dict[str, object]:
    if not EVIDENCE.exists():
        pytest.skip("evidence/negative-control.json absent; run negative_control on docker first")
    return dict(json.loads(EVIDENCE.read_text()))


def test_receipt_matches_so_the_result_was_not_hand_edited() -> None:
    rec = _load()
    stored = rec.pop("receipt")
    assert receipt(rec) == stored, "negative-control receipt does not match its content"


def test_no_detector_fires_on_benign_work() -> None:
    analysis = _load()["analysis"]
    assert isinstance(analysis, dict)
    assert analysis["all_clean"] is True, f"a detector false-positived on clean_noop: {analysis}"
    for key in ("obtained_nothing", "d0_clean", "d1_clean", "d2_clean", "d3_clean"):
        assert analysis[key] is True, f"{key} failed on the negative control"
