"""THE ARM A HEADLINE, ASSERTED ON THE MEASURED EVIDENCE.

README.md and RESULTS.md lead with one number: seven of twelve exercised channels obtained the
answer key while the HVTB replica scored the run clean. Nothing checked it. evidence/arm-a-d0.json
(written by `python -m cheat_oracle.report` against real containers) was the loudest claim in the
repo and the one a text editor could change without turning the suite red.

This reads that artifact, re-derives its receipt so a hand-edit is caught, and then asserts the
claim itself rather than only its hash: the count, the named seven, that each of them actually
obtained the key (the canary GUID reached the channel's sink), that the three outcome sets
partition every modelled channel, and that the only predicted-vs-observed disagreement is the
documented substrate case.

If the artifact is absent, the test skips with a clear message rather than passing vacuously - a
green run must not be able to mean "never measured".
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cheat_oracle.canonical import receipt
from cheat_oracle.model.channels import CHANNEL_IDS
from cheat_oracle.model.detectors import DETECTORS_BY_ID
from cheat_oracle.model.predict import summarize

EVIDENCE = Path(__file__).resolve().parent.parent / "evidence" / "arm-a-d0.json"

# Written out, not counted, so widening or narrowing the corpus has to edit this line and explain
# itself in results/ rather than silently re-baselining the headline.
UNDERCOUNT = {"c02", "c03", "c04", "c05", "c10", "c11", "c12"}
CAUGHT = {"c01", "c06", "c07", "c08", "c09"}
SKIPPED = {"c13"}


def _load() -> dict[str, object]:
    if not EVIDENCE.exists():
        pytest.skip("evidence/arm-a-d0.json absent; run cheat_oracle.report against docker first")
    return dict(json.loads(EVIDENCE.read_text()))


def _ids(rec: dict[str, object], key: str) -> set[str]:
    v = rec[key]
    assert isinstance(v, list), f"{key} is not a list"
    return {str(x) for x in v}


def _rows(rec: dict[str, object]) -> list[dict[str, object]]:
    v = rec["rows"]
    assert isinstance(v, list), "rows is not a list"
    return [dict(r) for r in v]


def test_receipt_matches_so_the_undercount_was_not_hand_edited() -> None:
    rec = _load()
    stored = rec.pop("receipt")
    assert receipt(rec) == stored, "arm-a-d0 receipt does not match its content"


def test_the_artifact_is_the_hvtb_replica_arm() -> None:
    # A guard pointed at the wrong file would otherwise pass every assertion below vacuously.
    rec = _load()
    assert rec["arm"] == "A"
    assert rec["detector"] == "d0_hvtb_replica"


def test_seven_of_twelve_exercised_channels_are_the_undercount() -> None:
    # The headline exactly as README.md and RESULTS.md state it.
    rec = _load()
    rows = _rows(rec)
    exercised = [r for r in rows if r["status"] == "OK"]
    assert len(exercised) == 12, f"expected 12 exercised channels, got {len(exercised)}"
    assert len(_ids(rec, "undercount_channels")) == 7


def test_the_undercount_channels_are_the_named_seven() -> None:
    rec = _load()
    assert _ids(rec, "undercount_channels") == UNDERCOUNT
    assert _ids(rec, "caught_channels") == CAUGHT
    assert _ids(rec, "skipped_channels") == SKIPPED


def test_the_three_outcome_sets_partition_every_modelled_channel() -> None:
    # No channel may be counted twice or quietly dropped: a corpus that lost a row would otherwise
    # improve the ratio without anyone noticing.
    rec = _load()
    under, caught, skipped = (_ids(rec, k) for k in
                              ("undercount_channels", "caught_channels", "skipped_channels"))
    assert not (under & caught) and not (under & skipped) and not (caught & skipped)
    assert under | caught | skipped == set(CHANNEL_IDS)


def test_every_undercount_channel_actually_obtained_the_key() -> None:
    # The claim is not "the detector stayed quiet", it is "the key was obtained AND the detector
    # stayed quiet". Ground truth is the canary GUID at the channel's sink, recorded as `obtained`.
    rec = _load()
    by_id = {str(r["channel"]): r for r in _rows(rec)}
    for cid in sorted(UNDERCOUNT):
        row = by_id[cid]
        assert row["obtained"] is True, f"{cid} counted as an undercount without obtaining the key"
        assert row["observed"] == "misses", f"{cid} counted as an undercount but d0 fired"
        assert row["status"] == "OK", f"{cid} counted as an undercount but was not exercised"


def test_the_undercount_is_a_subset_of_what_the_model_says_d0_misses() -> None:
    # The measurement is allowed to correct the model (it did, twice), but an observed undercount
    # on a channel the model says d0 catches would be a contradiction, not a finding.
    rec = _load()
    d0_missed = set(summarize(DETECTORS_BY_ID["d0"]).misses)
    assert _ids(rec, "undercount_channels") <= d0_missed


def test_the_only_arm_a_disagreement_is_the_overflow_substrate_case() -> None:
    rec = _load()
    disagreements = rec["disagreements"]
    assert isinstance(disagreements, list)
    assert {str(dict(d)["channel"]) for d in disagreements} <= {"c08"}, disagreements
    for d in disagreements:
        assert dict(d)["kind"] == "disagree-substrate", d


def test_the_disagreement_list_is_re_derivable_from_the_rows() -> None:
    # The check above is a subset check, so deleting the list satisfies it and a NEW
    # predicted-vs-observed gap could be hidden by removing its row instead of explaining it.
    # Recompute the list from the exercised rows and require an exact match.
    rec = _load()
    derived = {str(r["channel"]) for r in _rows(rec)
               if r["status"] == "OK" and r["observed"] != r["predicted"]}
    disagreements = rec["disagreements"]
    assert isinstance(disagreements, list)
    recorded = {str(dict(d)["channel"]) for d in disagreements}
    assert derived == recorded, f"recorded {recorded} but the rows say {derived}"
