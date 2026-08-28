"""Integrity of the model itself: the ids are clean, the matrix is complete, and predict is a
total deterministic function. None of this touches a container; it guards the data the empirical
harness will later grade against, so that a rename or a dropped row cannot silently make the
observed-vs-predicted diff meaningless.
"""

from __future__ import annotations

import pytest

from cheat_oracle.model.channels import CHANNEL_IDS, CHANNELS
from cheat_oracle.model.detectors import DETECTOR_IDS, DETECTORS
from cheat_oracle.model.layers import Verdict
from cheat_oracle.model.predict import PREDICTED, predict


def test_channel_ids_are_unique_and_well_formed() -> None:
    assert len(CHANNEL_IDS) == len(set(CHANNEL_IDS))
    assert all(cid[0] == "c" and cid[1:].isdigit() for cid in CHANNEL_IDS)


def test_detector_ids_are_unique_and_well_formed() -> None:
    assert len(DETECTOR_IDS) == len(set(DETECTOR_IDS))
    assert all(did[0] == "d" and did[1:].isdigit() for did in DETECTOR_IDS)


def test_exactly_one_target_and_one_fix() -> None:
    assert sum(d.is_the_target for d in DETECTORS) == 1
    assert sum(d.is_the_fix for d in DETECTORS) == 1


def test_exactly_one_positive_control() -> None:
    assert sum(c.is_positive_control for c in CHANNELS) == 1


def test_matrix_is_complete() -> None:
    assert set(PREDICTED) == set(CHANNEL_IDS)
    for cid in CHANNEL_IDS:
        assert set(PREDICTED[cid]) == set(DETECTOR_IDS), f"{cid} missing detector columns"


def test_every_cell_has_a_verdict_and_a_nonempty_rationale() -> None:
    for cid in CHANNEL_IDS:
        for did in DETECTOR_IDS:
            cell = PREDICTED[cid][did]
            assert isinstance(cell.verdict, Verdict)
            assert cell.rationale.strip(), f"{cid}/{did} has an empty rationale"
            assert cell.channel_id == cid and cell.detector_id == did


def test_predict_is_deterministic() -> None:
    # Called twice, identical output. A prediction that changed between calls would not be one.
    for ch in CHANNELS:
        for d in DETECTORS:
            a, b = predict(ch, d), predict(ch, d)
            assert a == b


def test_object_reaching_channels_declare_visible_layers() -> None:
    # A modelling-integrity guard: an OBJECT_REACHING channel with an empty visible set would
    # silently be predicted MISS everywhere, which is almost never what was meant.
    from cheat_oracle.model.layers import ObtainClass

    for ch in CHANNELS:
        if ch.obtain_class is ObtainClass.OBJECT_REACHING:
            assert ch.visible_layers, f"{ch.id} is OBJECT_REACHING but declares no visible layers"


def test_detector_attack_channels_declare_a_subclass() -> None:
    from cheat_oracle.model.layers import ObtainClass

    for ch in CHANNELS:
        if ch.obtain_class is ObtainClass.DETECTOR_ATTACK:
            assert ch.attack_subclass is not None, f"{ch.id} attack channel with no subclass"


@pytest.mark.parametrize("cid", CHANNEL_IDS)
def test_channel_has_a_reality_note(cid: str) -> None:
    from cheat_oracle.model.channels import CHANNELS_BY_ID

    assert len(CHANNELS_BY_ID[cid].reality) > 30, f"{cid} needs an honest reality note"
