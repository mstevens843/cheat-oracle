"""The ledger must chain, verify, and break loudly when edited - and attribution must classify an
inode as key, object-store, or neither with no room for a copy to sneak in as the key."""

from __future__ import annotations

import json
from pathlib import Path

from cheat_oracle.ledger.attribution import AttributionSet, InodeKey
from cheat_oracle.ledger.ledger import Ledger


def test_attribution_key_hardlink_object_store_and_miss() -> None:
    a = AttributionSet(
        key=InodeKey(65025, 249301),
        object_store=frozenset({InodeKey(65025, 300100)}),
    )
    assert a.classify(65025, 249301) == "key"          # the key, or any hardlink (same inode)
    assert a.classify(65025, 300100) == "object_store"  # a git object holding the blob
    assert a.classify(65025, 999999) is None            # a copy on a different inode: not the key


def test_ledger_appends_and_verifies(tmp_path: Path) -> None:
    p = tmp_path / "chain.jsonl"
    led = Ledger(p)
    led.append({"i": 0, "kind": "key", "path": "/app/admin/key.txt"})
    led.append({"i": 1, "kind": "object_store", "path": "/app/.git/objects/ab/cd"})
    ok, broken = Ledger.verify(p)
    assert ok and broken == -1
    assert led.count == 2


def test_ledger_detects_tampering(tmp_path: Path) -> None:
    p = tmp_path / "chain.jsonl"
    led = Ledger(p)
    led.append({"kind": "key", "n": 0})
    led.append({"kind": "key", "n": 1})
    led.append({"kind": "key", "n": 2})
    # edit the first record's content on disk, leave its hash line intact
    lines = p.read_text().splitlines()
    first = json.loads(lines[0])
    first["record"]["n"] = 99
    lines[0] = json.dumps(first, sort_keys=True)
    p.write_text("\n".join(lines) + "\n")
    ok, broken = Ledger.verify(p)
    assert not ok and broken == 0


def test_ledger_detects_deletion(tmp_path: Path) -> None:
    p = tmp_path / "chain.jsonl"
    led = Ledger(p)
    for n in range(4):
        led.append({"kind": "key", "n": n})
    lines = p.read_text().splitlines()
    del lines[1]  # drop the second record; record 2's prev no longer matches
    p.write_text("\n".join(lines) + "\n")
    ok, broken = Ledger.verify(p)
    assert not ok and broken == 1
