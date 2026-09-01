"""Final verdict certification for canary-mint's ledger.

The monitor records attributed reads in memory and appends the same events to a hash-chained
ledger. The final verdict is only certifiable if those two views agree: a valid chain exists with
exactly one record per attributed event. That catches the tamper cases a plain hash-chain check
cannot catch by itself, including deleting the last record from an otherwise valid chain.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .ledger import Ledger


@dataclass(frozen=True)
class LedgerAudit:
    ok: bool
    reason: str
    expected_records: int
    observed_records: int
    broken_index: int

    def as_json(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "reason": self.reason,
            "expected_records": self.expected_records,
            "observed_records": self.observed_records,
            "broken_index": self.broken_index,
        }


@dataclass(frozen=True)
class CertifiedVerdict:
    verdict: str
    audit: LedgerAudit

    def as_json(self) -> dict[str, object]:
        return {"verdict": self.verdict, "ledger_verify": self.audit.as_json()}


def _count_records(path: Path) -> int:
    with path.open(encoding="utf-8") as fh:
        return sum(1 for _ in fh)


def audit_ledger(path: Path, expected_records: int) -> LedgerAudit:
    """Verify the ledger chain and that it has exactly the expected number of records."""
    if expected_records < 0:
        raise ValueError("expected_records must be non-negative")

    if not path.exists():
        if expected_records == 0:
            return LedgerAudit(True, "absent-empty", expected_records, 0, -1)
        return LedgerAudit(False, "missing", expected_records, 0, 0)

    try:
        observed = _count_records(path)
    except OSError:
        return LedgerAudit(False, "unreadable", expected_records, -1, 0)

    ok, broken = Ledger.verify(path)
    if not ok:
        return LedgerAudit(False, "broken", expected_records, observed, broken)

    if observed != expected_records:
        return LedgerAudit(
            False,
            "count-mismatch",
            expected_records,
            observed,
            min(observed, expected_records),
        )

    return LedgerAudit(True, "ok", expected_records, observed, -1)


def certify_verdict(
    ledger_path: Path,
    fired: Mapping[str, int],
    *,
    integrity_void: bool,
) -> CertifiedVerdict:
    """Return the final monitor verdict after ledger verification.

    ``fired`` is the monitor's in-memory count of attributed accesses by kind. A non-empty count
    can only certify FIRE if the on-disk ledger verifies and has the same record count. If the
    monitor saw its own integrity fail, or if the ledger cannot certify the in-memory count, the
    verdict is VOID.
    """
    expected_records = 0
    for kind, count in fired.items():
        if count < 0:
            raise ValueError(f"negative fired count for {kind}: {count}")
        expected_records += count

    audit = audit_ledger(ledger_path, expected_records)
    if integrity_void or not audit.ok:
        return CertifiedVerdict("void", audit)
    if expected_records:
        return CertifiedVerdict("fires", audit)
    return CertifiedVerdict("misses", audit)
