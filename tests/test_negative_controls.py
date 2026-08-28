"""The false-positive floor, asserted on measured evidence. A measured 7-of-12 undercount is only
trustworthy if the detectors do not also fire on benign work; NEGATIVE_CONTROL_SUBJECT (clean_noop)
does legitimate work that never reads the key, and every detector must score it clean.

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


def _observed() -> dict[str, object]:
    o = _load()["observed"]
    assert isinstance(o, dict), "observed is not an object"
    return dict(o)


def test_the_control_subject_is_the_benign_one_and_it_took_nothing() -> None:
    # Without this the artifact could record a clean run of any subject, including one that never
    # ran, and every assertion above would still pass.
    o = _observed()
    assert o["subject"] == "clean_noop"
    assert o["obtained"] is False


def test_the_clean_verdicts_are_re_derivable_from_the_observed_run() -> None:
    # analysis is a summary of observed. Deriving it back means flipping a summary flag alone
    # disagrees with the run beneath it, so a false positive cannot be hidden in the summary.
    o, a = _observed(), _load()["analysis"]
    assert isinstance(a, dict)
    d2_fired, d3_fired = o["d2_fired"], o["d3_fired"]
    assert isinstance(d2_fired, dict) and isinstance(d3_fired, dict)
    derived = {
        "obtained_nothing": o["obtained"] is False,
        "d0_clean": o["d0_flagged"] is False,
        "d1_clean": o["d1_flagged"] is False,
        "d2_clean": o["d2"] == "misses" and not any(d2_fired.values()),
        "d3_clean": o["d3"] == "misses" and not any(d3_fired.values()),
    }
    for key, value in derived.items():
        assert a[key] is value, f"{key}: summary says {a[key]}, the run says {value}"
    assert a["all_clean"] is all(derived.values())
