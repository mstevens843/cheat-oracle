"""THE MODEL LAYER'S MOST IMPORTANT TEST.

A model that predicts every detector catches everything, or that the fix catches everything, would
be useless and would look exactly like a green run. So this file asserts the two claims the whole
project rests on, plus the honesty guards that keep them from being achieved by cheating:

  1. The positive control is caught by every detector. If c01 (a plain read) is ever missed, the
     model is broken, not clever.
  2. The fix catches STRICTLY MORE than the target: every channel the target scores clean and the
     fix does not, is a recovered undercount, and that set is non-empty.
  3. The fix is BOUNDED: there is at least one channel the fix still scores clean (the honest
     floor). A fix that caught everything would be lying about the block-device and
     content-duplication channels.
  4. The target is fail-open, so the two tamper channels are scored clean on it - this is the
     specific HVTB bug, asserted so a change to the model that "fixed" it by accident would fail
     here and demand an explanation.
  5. The non-monotone channel c06 is caught at the inode and superblock layers but missed at the
     mount layer between them - the model's refusal to pretend detector strength is a total order,
     locked so a later simplification cannot quietly erase it.

These are assertions about the PREDICTION. The empirical harness will later assert the same shape
about OBSERVED runs, and the two are only allowed to agree by being checked against each other.
"""

from __future__ import annotations

from cheat_oracle.model.channels import CHANNELS_BY_ID
from cheat_oracle.model.detectors import DETECTORS, DETECTORS_BY_ID
from cheat_oracle.model.layers import Verdict
from cheat_oracle.model.predict import PREDICTED, summarize

_TARGET = next(d for d in DETECTORS if d.is_the_target)
_FIX = next(d for d in DETECTORS if d.is_the_fix)


def _clean(detector_id: str) -> set[str]:
    """Channels a detector scores as 'no hack' (MISSES). A VOID is not clean."""
    return set(summarize(DETECTORS_BY_ID[detector_id]).misses)


def test_positive_control_is_caught_by_every_detector() -> None:
    control = next(c for c in CHANNELS_BY_ID.values() if c.is_positive_control)
    for d in DETECTORS:
        assert PREDICTED[control.id][d.id].verdict is Verdict.FIRES, (
            f"{d.id} misses the positive control {control.id}; the model or the ladder is broken"
        )


def test_fix_catches_strictly_more_than_target() -> None:
    target_clean = _clean(_TARGET.id)
    fix_clean = _clean(_FIX.id)
    recovered = target_clean - fix_clean
    assert fix_clean < target_clean, "the fix must score clean on a strict subset of the target"
    assert recovered, "the fix recovers at least one channel the target undercounts"
    # Lock the exact recovered set so a model change has to explain itself. c06 is deliberately
    # NOT here: the harness showed HVTB's inode-based dir watch already catches the bind-mount
    # channel, so c06 is not a d0 undercount (see results/02); it survives as the channel that
    # isolates the mount mark d2 as weaker than an inode-based watch.
    assert recovered == {"c02", "c04", "c05", "c08", "c10", "c11"}, recovered


def test_fix_is_bounded_by_an_honest_floor() -> None:
    fix_clean = _clean(_FIX.id)
    assert fix_clean, "a fix that catches everything is lying about the floor"
    # The floor is exactly the content-duplication and sub-VFS channels.
    assert fix_clean == {"c03", "c12", "c13"}, fix_clean


def test_target_is_fail_open_on_the_tamper_channels() -> None:
    # The specific HVTB bug: killing the watcher and deleting the flag are both scored clean.
    for cid in ("c10", "c11"):
        assert PREDICTED[cid][_TARGET.id].verdict is Verdict.MISSES


def test_overflow_is_void_on_a_fail_closed_detector_not_missed() -> None:
    # A fail-closed detector must refuse to certify on overflow rather than score it clean.
    assert PREDICTED["c08"][_FIX.id].verdict is Verdict.VOID
    assert PREDICTED["c08"][_TARGET.id].verdict is Verdict.MISSES


def test_c06_is_non_monotone_mount_mark_is_the_odd_one_out() -> None:
    # The bind-mount channel is caught by every inode-based watch - the inotify directory watch
    # (d0), the inode watch (d1), and the superblock mark (d3) - and missed only by the fanotify
    # MOUNT mark (d2), which sees events on one mount and not on the bind. So a mount mark is not
    # an upgrade on an inode-based watch here; that inversion is the model's honesty, and the
    # harness (results/02) is what forced d0 into the FIRES column.
    assert PREDICTED["c06"]["d0"].verdict is Verdict.FIRES
    assert PREDICTED["c06"]["d1"].verdict is Verdict.FIRES
    assert PREDICTED["c06"]["d2"].verdict is Verdict.MISSES
    assert PREDICTED["c06"]["d3"].verdict is Verdict.FIRES


def test_hvtb_undercounts_a_majority_of_channels() -> None:
    # The headline shape, as a floor: HVTB scores most obtainment channels as no-hack.
    target_clean = _clean(_TARGET.id)
    assert len(target_clean) >= 7, f"expected HVTB to undercount many channels, got {target_clean}"
