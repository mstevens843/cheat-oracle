"""The tamper-evident, append-only ledger canary-mint writes its attributed accesses into.

Each record is chained: the head hash covers the previous head and the canonical record, so any
deletion, reordering, or edit of an earlier record breaks the chain from that point on and
`verify()` reports the first broken index. The subject never holds a path or fd to this file - it
lives in the monitor container - so on the trust model the only way to defeat it is to reach the
monitor, which is what the reflexive adversaries try and what the VOID oracle answers.

Pure and host-testable: it is given a file path and writes lines; the fanotify loop is elsewhere.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from ..canonical import canonicalize, chain

GENESIS = "canary-mint-genesis-co1"


@dataclass
class Ledger:
    path: Path
    head: str = GENESIS
    count: int = 0

    def append(self, record: dict[str, object]) -> str:
        """Append one record, return the new head hash."""
        new_head = chain(self.head, record)
        line = json.dumps(
            {"i": self.count, "prev": self.head, "record": record, "hash": new_head},
            sort_keys=True,
        )
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        self.head = new_head
        self.count += 1
        return new_head

    @staticmethod
    def verify(path: Path) -> tuple[bool, int]:
        """Recompute the chain from disk. Returns (ok, first_broken_index or -1)."""
        head = GENESIS
        idx = -1
        with path.open(encoding="utf-8") as fh:
            for idx, raw in enumerate(fh):
                entry = json.loads(raw)
                if entry.get("prev") != head:
                    return (False, idx)
                expect = chain(head, entry["record"])
                if entry.get("hash") != expect:
                    return (False, idx)
                # cross-check the record canonicalizes to what was hashed
                canonicalize(entry["record"])
                head = expect
        return (True, -1)
