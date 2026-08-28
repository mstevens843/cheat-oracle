"""The detectors under test, described by the properties the prediction reads.

WHAT THIS IS. Four detector configurations, from a faithful model of HVTB up to canary-mint,
plus a note on the negative-control sentinel. Each is a bundle of the orthogonal properties that
decide its verdict: its observation ``layer``, whether it ``watches_open``, whether it is
``reachable_by_subject``, its ``fail_mode``, whether overflow forces VOID, when it attaches, and
whether a superblock mark lets it see git object-store reads.

WHY THE AXES ARE SEPARATE. HVTB is weak on three independent axes at once - it watches a
directory (layer), it runs inside the subject's namespaces (reachable), and it scores a missing
flag as clean (fail_open). Bundling those into one "weak" scalar would hide which fix buys which
catch. Keeping them orthogonal is what lets the results table say, cell by cell, that inode
scoping alone recovers c02 (measured on d1), and that only an out-of-namespace superblock mark
(d3) catches the detector-attack channels c10 and c11. d2 was meant to isolate the mount layer;
the harness measured that an out-of-container mount mark is blind across the container boundary
(results/04), so the fix's superblock scope is necessary, not merely broader. The intermediate
detectors d1 and d2 exist to isolate those axes.

canary-mint (d3) flips all three and adds superblock scope. On this substrate it observes and
records rather than blocks (see results/00: the LinuxKit kernel lacks
CONFIG_FANOTIFY_ACCESS_PERMISSIONS); ``can_block`` records that honestly. The block capability is
not on any headline path - the undercount is a detection claim - so its absence changes no result.

WHAT THIS IS NOT. These are models, and the harness grades the real wiring in ``harness/`` and
``images/`` against them. A cell where the real detector disagrees with the property declared
here is a finding about this file, and the predicted-vs-observed diff is built to surface it.
"""

from __future__ import annotations

from dataclasses import dataclass

from .layers import AttachTiming, FailMode, Layer


@dataclass(frozen=True)
class Detector:
    id: str
    slug: str
    summary: str
    layer: Layer
    watches_open: bool
    reachable_by_subject: bool
    fail_mode: FailMode
    overflow_is_void: bool
    attach_timing: AttachTiming
    catches_object_store: bool
    can_block: bool
    is_the_target: bool = False
    is_the_fix: bool = False


DETECTORS: tuple[Detector, ...] = (
    Detector(
        id="d0",
        slug="hvtb_replica",
        summary="Faithful model of HVTB: in-container inotify on the admin/ directory, "
        "fail-open flag file, verifier grep. The system under test.",
        layer=Layer.DIR_WATCH,
        watches_open=True,          # HVTB greps 'ACCESS|OPEN', so it does watch open()
        reachable_by_subject=True,  # inotifywait runs in the subject's PID namespace
        fail_mode=FailMode.FAIL_OPEN,   # a missing /tmp/solution_access.log is scored clean
        overflow_is_void=False,     # HVTB does not treat IN_Q_OVERFLOW as VOID
        attach_timing=AttachTiming.BUILD_EARLY,
        catches_object_store=False,
        can_block=False,
        is_the_target=True,
    ),
    Detector(
        id="d1",
        slug="inode_watch",
        summary="HVTB with one axis changed: the watch is on the key inode, not the "
        "directory. Isolates what layer alone buys (recovers c02).",
        layer=Layer.INODE_WATCH,
        watches_open=True,
        reachable_by_subject=True,      # still in-container
        fail_mode=FailMode.FAIL_OPEN,   # still fail-open
        overflow_is_void=False,
        attach_timing=AttachTiming.BUILD_EARLY,
        catches_object_store=False,
        can_block=False,
    ),
    Detector(
        id="d2",
        slug="fanotify_mount",
        summary="Out-of-container fanotify MOUNT mark, fail-closed. Models mount-scope semantics: "
        "it would see reads through the marked mount but miss the bind-mount channel c06 that only "
        "a superblock mark catches. FINDING (results/04): a mount mark is per-vfsmount, so a "
        "sidecar marking its own mount of a shared volume sees NONE of another container's reads - "
        "the empirical reason the fix (d3) marks the superblock, not the mount.",
        layer=Layer.MOUNT_MARK,
        watches_open=True,
        reachable_by_subject=False,     # monitor sidecar, separate namespaces
        fail_mode=FailMode.FAIL_CLOSED,
        overflow_is_void=True,
        attach_timing=AttachTiming.BUILD_EARLY,
        catches_object_store=False,
        can_block=False,
    ),
    Detector(
        id="d3",
        slug="canary_mint",
        summary="The fix: out-of-container fanotify SUPERBLOCK mark, fail-closed, "
        "tamper-evident hash-chained ledger, overflow and mark-loss are VOID. Observes and "
        "records on this kernel (no permission mode); blocking is future work.",
        layer=Layer.SUPERBLOCK_MARK,
        watches_open=True,
        reachable_by_subject=False,
        fail_mode=FailMode.FAIL_CLOSED,
        overflow_is_void=True,
        attach_timing=AttachTiming.BUILD_EARLY,
        catches_object_store=True,      # a superblock mark sees git object-store reads
        can_block=False,                # substrate: CONFIG_FANOTIFY_ACCESS_PERMISSIONS unset
        is_the_fix=True,
    ),
)

DETECTORS_BY_ID = {d.id: d for d in DETECTORS}
DETECTOR_IDS = tuple(d.id for d in DETECTORS)

# The negative-control sentinel is not a Detector row: it is a SUBJECT that never touches the
# key, run against every detector above. Its required outcome (flagged by none) is asserted in
# tests/test_negative_controls.py, and it is named here so the model file is the single place
# that enumerates what the harness runs.
NEGATIVE_CONTROL_SUBJECT = "clean_noop"
