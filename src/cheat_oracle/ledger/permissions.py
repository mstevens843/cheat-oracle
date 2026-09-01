"""Pure fanotify permission-event decisions for canary-mint.

The Linux monitor script is intentionally thin: it turns kernel events into an attribution kind,
then asks this module whether a permission event should be allowed or denied. Keeping the decision
pure makes the BLOCK=1 path testable even on kernels that cannot emit permission events.
"""

from __future__ import annotations

import errno
from dataclasses import dataclass

FAN_OPEN = 0x20
FAN_ACCESS = 0x1
FAN_Q_OVERFLOW = 0x4000
FAN_OPEN_PERM = 0x10000
FAN_ACCESS_PERM = 0x20000
FAN_CLASS_PRE_CONTENT = 0x8

FAN_ALLOW = 0x01
FAN_DENY = 0x02

OBSERVE_EVENT_MASK = FAN_OPEN | FAN_ACCESS
BLOCK_EVENT_MASK = FAN_OPEN_PERM | FAN_ACCESS_PERM
PERMISSION_MASK = FAN_OPEN_PERM | FAN_ACCESS_PERM
UNSUPPORTED_PERMISSION_ERRNOS = frozenset({errno.EINVAL, errno.ENOSYS})


@dataclass(frozen=True)
class PermissionDecision:
    response: int
    denied: bool
    record_kind: str | None


def event_mask(blocking: bool) -> int:
    """Return the fanotify event mask for the selected monitor mode."""
    return BLOCK_EVENT_MASK if blocking else OBSERVE_EVENT_MASK


def is_permission_event(mask: int) -> bool:
    return bool(mask & PERMISSION_MASK)


def integrity_failure_reason(mask: int, event_fd: int) -> str | None:
    """Return a fail-closed reason for lost or malformed fanotify events."""
    if mask & FAN_Q_OVERFLOW:
        return "queue-overflow"
    if event_fd < 0:
        return "malformed-negative-fd"
    return None


def decide_permission(kind: str | None) -> PermissionDecision:
    """Deny attributed answer-key/object-store reads; allow everything else."""
    if kind is None:
        return PermissionDecision(FAN_ALLOW, False, None)
    return PermissionDecision(FAN_DENY, True, kind)


def setup_failure_verdict(
    *,
    blocking: bool,
    operation: str,
    errno_value: int,
    detector: str,
) -> dict[str, object]:
    """Classify fanotify setup failures without mistaking missing support for evidence."""
    if blocking and errno_value in UNSUPPORTED_PERMISSION_ERRNOS:
        return {
            "detector": detector,
            "mode": "block",
            "verdict": "gated",
            "reason": f"{operation} permission events unsupported errno={errno_value}",
            "errno": errno_value,
        }
    return {
        "detector": detector,
        "mode": "block" if blocking else "observe",
        "verdict": "error",
        "reason": f"{operation} errno={errno_value}",
        "errno": errno_value,
    }
