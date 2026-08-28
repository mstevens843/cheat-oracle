"""c13, the honest floor, measured. A raw read of the backing block device reconstructs the key
below the VFS, so no path/inode/mount/superblock watch fires - canary-mint included. This drives the
privileged floor probe (images/floor) and records the result, or reports GATED if the substrate
refuses the loop device or mount. The floor is never silently claimed as measured.

`uv run python -m cheat_oracle.harness.floor_c13`   (needs docker + --privileged loop devices)
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from ..canonical import receipt

FLOOR_IMAGE = "cheat-oracle/floor:dev"
_ROOT = Path(__file__).resolve().parents[3]


def _guid() -> str:
    return (_ROOT / "images" / "subject" / "harness" / "GUID").read_text().strip()


def run_probe(timeout: float = 120.0) -> dict[str, object]:
    proc = subprocess.run(
        ["docker", "run", "--rm", "--privileged", "-e", f"GUID={_guid()}", FLOOR_IMAGE],
        capture_output=True, text=True, timeout=timeout, check=False,
    )
    for line in proc.stdout.splitlines():
        if line.startswith("FLOOR_RESULT "):
            return dict(json.loads(line[len("FLOOR_RESULT ") :]))
    return {"gated": True, "reason": "no FLOOR_RESULT emitted",
            "stderr": proc.stderr[-400:], "rc": proc.returncode}


def main() -> int:
    result = run_probe()
    if result.get("gated"):
        print(f"c13 floor GATED: {result.get('reason')}")
        print("No evidence written - the floor is not claimed as measured on this substrate.")
        return 0
    record: dict[str, object] = {"channel": "c13", "probe": result}
    record["receipt"] = receipt(record)
    holds = bool(result.get("floor_holds"))
    print("c13 honest floor - a raw block-device read below the VFS:")
    print(f"  obtained the key via the raw device : {result.get('obtained_via_raw_device')}")
    print(f"  fanotify fired on the VFS read      : {result.get('fanotify_fired_on_vfs_read')}"
          "  (positive control: the mark is live)")
    print(f"  fanotify fired on the raw read      : {result.get('fanotify_fired_on_raw_read')}"
          "  (the floor: the fix does not see it)")
    print(f"  FLOOR HOLDS (obtained, VFS-fires, raw-silent): {holds}")
    out = _ROOT / "evidence" / "floor-c13.json"
    out.write_text(json.dumps(record, indent=2, sort_keys=True))
    print(f"\nreceipt: {record['receipt']}\nwrote {out}")
    return 0 if holds else 1


if __name__ == "__main__":
    raise SystemExit(main())
