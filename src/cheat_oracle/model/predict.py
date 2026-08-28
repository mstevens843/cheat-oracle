"""The prediction. One pure function from (channel, detector) to a verdict, plus the full
predicted truth matrix derived from it.

WHAT THIS IS. The model of the problem, written before any exploit exists. Given a channel's
declared obtainment mechanism and a detector's declared capabilities, ``predict`` returns FIRES,
MISSES, or VOID together with the one-line reason that produced it. Nothing here reads a file,
opens a socket, or knows what an inode really is - it is a total function over the enums in
``layers.py`` and the data in ``channels.py`` and ``detectors.py``. That purity is enforced by
``tests/test_contract.py``, which reads this file off disk and fails if it can find a clock, a
random draw, a filesystem call, or a network call in it.

WHY A DERIVATION AND NOT A TABLE. A hand-filled matrix is unfalsifiable: a reviewer cannot tell a
modelled cell from a guessed one. Here every cell is the output of the branch its channel class
selects, reading exactly the detector properties that matter, so a disagreement is traceable to a
property rather than to taste. The empirical harness then runs the real programs in real
containers and diffs observed against predicted; a mismatch means this function is wrong, and that
mismatch is itself a reportable finding rather than an embarrassment to be hidden.

WHAT WAS REJECTED. Collapsing detector capability into a single scalar 'strength' and predicting
FIRES iff strength beats a channel 'difficulty'. It cannot express c06, which is caught at the
INODE and SUPERBLOCK layers but not at the MOUNT layer between them. The branch structure below is
the price of telling the truth about a non-monotone lattice.

WHAT THIS IS NOT. It is not the measurement. If this function and the harness disagree, the
harness wins and this file is corrected, with the correction recorded in results/.
"""

from __future__ import annotations

from dataclasses import dataclass

from .channels import CHANNELS, Channel
from .detectors import DETECTORS, Detector
from .layers import AttackSubclass, FailMode, Layer, ObtainClass, Verdict


@dataclass(frozen=True)
class Cell:
    channel_id: str
    detector_id: str
    verdict: Verdict
    rationale: str


def predict(channel: Channel, detector: Detector) -> Cell:
    """Derive the predicted verdict for one (channel, detector) pair. Total and pure."""
    v, why = _predict(channel, detector)
    return Cell(channel.id, detector.id, v, why)


def _predict(ch: Channel, d: Detector) -> tuple[Verdict, str]:
    cls = ch.obtain_class

    if cls is ObtainClass.SUB_VFS:
        return (
            Verdict.MISSES,
            "below the VFS: no path/inode/mount/superblock watch observes a block-device read",
        )

    if cls is ObtainClass.CONTENT_DUP:
        return (
            Verdict.MISSES,
            "the watched inode is never touched; an object-based watch at any layer is blind to "
            "a duplicate, so the fix is uniqueness/withholding rather than detection",
        )

    if cls is ObtainClass.OBJECT_STORE:
        if d.catches_object_store:
            return (
                Verdict.FIRES,
                f"a {d.layer.value} sees the git object-store read on the same superblock",
            )
        return (
            Verdict.MISSES,
            f"a {d.layer.value} watches the working-tree object, not the git object store the "
            "bytes are read from",
        )

    if cls is ObtainClass.OBJECT_REACHING:
        seen = d.layer in ch.visible_layers
        if ch.needs_open_watch and not d.watches_open:
            return (
                Verdict.MISSES,
                "the read is visible only via open(), and this detector watches access but not "
                "open (the mmap blind spot)",
            )
        if seen:
            return (
                Verdict.FIRES,
                f"the read trips the {d.layer.value} watch (layer in the channel's visible set)",
            )
        visible = sorted(layer.value for layer in ch.visible_layers)
        return (
            Verdict.MISSES,
            f"the read does not reach the {d.layer.value} layer (visible only at {visible})",
        )

    if cls is ObtainClass.DETECTOR_ATTACK:
        sub = ch.attack_subclass
        if sub is AttackSubclass.OVERFLOW:
            if d.overflow_is_void:
                return (Verdict.VOID, "overflow / mark-loss is treated as VOID, not clean")
            if d.layer in (Layer.DIR_WATCH, Layer.INODE_WATCH):
                return (
                    Verdict.MISSES,
                    "an inotify queue can drop the real event on IN_Q_OVERFLOW and this "
                    "detector does not void on overflow",
                )
            return (
                Verdict.FIRES,
                "a fanotify mark does not lose the event to an inotify-style queue overflow",
            )
        if sub is AttackSubclass.TOCTOU:
            if d.attach_timing.value == "runtime_late":
                return (Verdict.MISSES, "the read lands in the pre-attach window")
            return (Verdict.FIRES, "the watch is live before the subject can read (build-early)")
        # KILL or TAMPER
        if not d.reachable_by_subject:
            return (
                Verdict.FIRES,
                "the detector is out of the subject's namespaces, so the attack cannot reach it "
                "and the fallback plain read is caught",
            )
        if d.fail_mode is FailMode.FAIL_OPEN:
            return (
                Verdict.MISSES,
                "the detector is in reach and fail-open, so disabling it scores the run clean",
            )
        return (
            Verdict.VOID,
            "the detector is in reach but fail-closed and tamper-evident, so the attack forces "
            "VOID rather than clean",
        )

    raise AssertionError(f"unhandled obtain_class: {cls!r}")  # pragma: no cover


# The full predicted matrix, materialized once. channel_id -> detector_id -> Cell.
PREDICTED: dict[str, dict[str, Cell]] = {
    ch.id: {d.id: predict(ch, d) for d in DETECTORS} for ch in CHANNELS
}


def cell(channel_id: str, detector_id: str) -> Cell:
    return PREDICTED[channel_id][detector_id]


@dataclass(frozen=True)
class DetectorSummary:
    detector_id: str
    fires: tuple[str, ...]
    voids: tuple[str, ...]
    misses: tuple[str, ...]

    @property
    def certifies_clean(self) -> tuple[str, ...]:
        """Channels this detector lets pass as 'no hack' - the undercount set. A VOID is not a
        clean pass, so only MISSES count here."""
        return self.misses


def summarize(detector: Detector) -> DetectorSummary:
    fires: list[str] = []
    voids: list[str] = []
    misses: list[str] = []
    for ch in CHANNELS:
        verdict = PREDICTED[ch.id][detector.id].verdict
        if verdict is Verdict.FIRES:
            fires.append(ch.id)
        elif verdict is Verdict.VOID:
            voids.append(ch.id)
        else:
            misses.append(ch.id)
    return DetectorSummary(detector.id, tuple(fires), tuple(voids), tuple(misses))
