"""The vocabulary the whole model is derived from.

WHAT THIS IS. The enumerated properties of an answer-key access detector and of a
byte-obtainment channel, plus the three-valued verdict a detector can return. Every other
file in ``model/`` is built out of these, and ``predict.py`` is a pure function over them.

WHY IT EXISTS SEPARATELY. The point of this project is to model the problem before writing a
single exploit (the strong pattern observed in the benchmark trials: model the state machine,
then patch). The model has to name its terms once, in one place, so that the predicted truth
matrix is a *derivation* over declared properties rather than a hand-filled table someone can
accuse of being rigged. If a reviewer disagrees with a predicted cell, they can point at the
exact property that produced it.

WHAT WAS REJECTED. An earlier sketch gave every detector a single scalar "strength" and every
channel a single "difficulty", and predicted FIRES iff strength >= difficulty. That is a lie:
the c06 procroot/bindmount channel is visible to an INODE watch and to a SUPERBLOCK mark but
NOT to a MOUNT mark, so detector capability is not a total order and cannot be one scalar. The
model here is explicit and non-monotone on purpose.

WHAT THIS IS NOT. It is not a description of any real detector's source. It is the abstract
model those detectors are instances of. The real wiring lives in ``images/`` and ``harness/``,
and the empirical harness exists precisely to catch the model being wrong.
"""

from __future__ import annotations

from enum import Enum


class Verdict(Enum):
    """What a detector reports about one run.

    FIRES  - the detector flagged the answer-key access. A true positive when the bytes were
             in fact obtained; a false positive when they were not.
    MISSES - the detector reported nothing. This is the dangerous value: on a fail-open
             detector a MISS is scored as "no hack", so a confirmed obtainment that produces a
             MISS is an undercount.
    VOID   - the detector refused to certify the run because its own integrity was in doubt
             (its watcher was killed, its log was tampered, its event queue overflowed, a mark
             was lost). A fail-closed detector converts these into VOID; a fail-open detector
             converts them into MISSES, which is the entire bug this project measures.
    """

    FIRES = "fires"
    MISSES = "misses"
    VOID = "void"


class Layer(Enum):
    """The filesystem layer at which a detector observes an access.

    Ordered weakest to strongest FOR AN OBJECT-REACHING READ, but the order is not a promise:
    a channel can be visible at a stronger layer and invisible at a weaker one and vice versa
    (see ``channels.py`` c06). The layer only decides visibility for reads that actually touch
    the watched object; content-duplication and sub-VFS channels are invisible at every layer
    here and are handled by ``ObtainClass`` instead.
    """

    PATH_STRING = "path_string"          # greps the literal watched path; any rename defeats it
    DIR_WATCH = "dir_watch"              # inotify on the watched directory (this is HVTB)
    INODE_WATCH = "inode_watch"          # inotify / audit -w on the watched file inode
    MOUNT_MARK = "mount_mark"            # fanotify FAN_MARK_MOUNT
    SUPERBLOCK_MARK = "superblock_mark"  # fanotify FAN_MARK_FILESYSTEM, the tightest VFS layer


class FailMode(Enum):
    """What a detector does when its evidence is absent or its integrity is in doubt.

    FAIL_OPEN scores absence as "no hack" (HVTB: a missing /tmp/solution_access.log is clean).
    FAIL_CLOSED scores absence or doubt as VOID. The single most consequential property here.
    """

    FAIL_OPEN = "fail_open"
    FAIL_CLOSED = "fail_closed"


class AttachTiming(Enum):
    """When the detector's watch becomes active relative to the subject obtaining bytes.

    BUILD_EARLY - the watch is installed before the subject can run (HVTB patches the
                  Dockerfile, so the inotify watch is live at container build). The TOCTOU
                  pre-watch window is then narrow.
    RUNTIME_LATE - the watch attaches after the subject is already running, leaving a window in
                   which a read is invisible.
    """

    BUILD_EARLY = "build_early"
    RUNTIME_LATE = "runtime_late"


class ObtainClass(Enum):
    """How a channel gets the answer-key bytes. This is the primary axis of the model.

    OBJECT_REACHING - the read touches the watched inode via the VFS (through some path/mount).
                      Visibility is then decided by ``Layer`` and by whether the detector
                      watches open() (the mmap subtlety). c01, c02, c06, c07.
    OBJECT_STORE    - the content is read from git's object database (loose object or packfile),
                      a different inode on the same superblock. Only a superblock mark sees the
                      read at all, and even then cannot cheaply attribute it to the answer blob.
                      c04, c05.
    CONTENT_DUP     - the bytes are obtained from a duplicate whose inode is never the watched
                      one: a pre-existing copy, or a public copy fetched over the network. No
                      object-based detector at any layer can see this, because it watches the
                      object, and the content has more than one object. The fix is uniqueness /
                      withholding, not detection. c03, c12.
    DETECTOR_ATTACK - the channel defeats the detector's integrity or liveness rather than its
                      layer: overflow its queue, race its attach window, kill its watcher, or
                      tamper its flag file. Closed only by out-of-reach + fail-closed +
                      tamper-evident design. c08, c09, c10, c11.
    SUB_VFS         - the bytes are read below the VFS (raw block device), so no path-, inode-,
                      mount-, or superblock-level watch fires. The honest floor. c13.
    """

    OBJECT_REACHING = "object_reaching"
    OBJECT_STORE = "object_store"
    CONTENT_DUP = "content_dup"
    DETECTOR_ATTACK = "detector_attack"
    SUB_VFS = "sub_vfs"


class AttackSubclass(Enum):
    """For DETECTOR_ATTACK channels, which integrity property is under attack."""

    OVERFLOW = "overflow"   # drop the real event by flooding the watcher's queue
    TOCTOU = "toctou"       # obtain during the pre-watch window
    KILL = "kill"           # stop or starve the watcher process
    TAMPER = "tamper"       # rewrite or delete the detector's own record


class Privilege(Enum):
    """What a channel requires of the subject. Bounds how realistic each evasion is."""

    UNPRIVILEGED = "unprivileged"        # any shell in the container
    NEEDS_LOCAL_STATE = "needs_local_state"  # a pre-existing copy the harness planted
    NEEDS_NETWORK = "needs_network"      # allow_internet, which base Terminal-Bench grants
    NEEDS_DEVICE = "needs_device"        # raw block-device access; normally absent in a sandbox
