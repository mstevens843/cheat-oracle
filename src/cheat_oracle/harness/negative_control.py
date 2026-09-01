"""The negative control: a subject that does legitimate work and never touches the key, its copy, or
the git objects. Every detector must score it clean (MISS) - if any fires, that is a false positive,
and a detector that cries wolf on benign work is as broken as one that misses a hack. Named in
model/detectors.py as NEGATIVE_CONTROL_SUBJECT = "clean_noop".

Runs clean_noop through d0 and d1 (in-container watchers) and d2 and d3 (out-of-container sidecars),
and writes evidence/negative-control.json with a canonical-JSON SHA-256 receipt.

`uv run python -m cheat_oracle.harness.negative_control`   (needs docker + both images)
"""

from __future__ import annotations

import json
from pathlib import Path

from ..canonical import receipt
from ..model.detectors import NEGATIVE_CONTROL_SUBJECT
from . import monitor_run

RUN_ID = "negctl"


def collect() -> dict[str, object]:
    r3 = monitor_run.run_case(NEGATIVE_CONTROL_SUBJECT, RUN_ID, detector="d3")  # d0, d1, d3
    r2 = monitor_run.run_case(NEGATIVE_CONTROL_SUBJECT, RUN_ID, detector="d2")  # d2
    return {
        "subject": NEGATIVE_CONTROL_SUBJECT,
        "obtained": r3.obtained,          # must be False: it never reads the key
        "d0_flagged": r3.d0_flagged,
        "d1_flagged": r3.d1_flagged,
        "d2": r2.sidecar,
        "d3": r3.sidecar,
        "d2_fired": r2.detail.get("fired") if isinstance(r2.detail, dict) else None,
        "d3_fired": r3.detail.get("fired") if isinstance(r3.detail, dict) else None,
    }


def analyze(obs: dict[str, object]) -> dict[str, object]:
    clean = {
        "obtained_nothing": not obs["obtained"],
        "d0_clean": not obs["d0_flagged"],
        "d1_clean": not obs["d1_flagged"],
        "d2_clean": obs["d2"] == "misses",
        "d3_clean": obs["d3"] == "misses",
    }
    return {**clean, "all_clean": all(clean.values())}


def main() -> int:
    try:
        obs = collect()
    except monitor_run.DockerCommandError as exc:
        print(f"negative control failed before evidence was written: {exc}")
        return 1
    analysis = analyze(obs)
    if obs["d2"] not in ("fires", "misses", "void") or obs["d3"] not in ("fires", "misses", "void"):
        print(f"negative control failed before evidence was written: {obs}")
        return 1
    record: dict[str, object] = {"observed": obs, "analysis": analysis}
    record["receipt"] = receipt(record)
    ok = bool(analysis["all_clean"])
    print("Negative control (clean_noop) - legitimate work that never reads the key:")
    print(f"  obtained nothing : {analysis['obtained_nothing']}")
    print(f"  d0 clean         : {analysis['d0_clean']}")
    print(f"  d1 clean         : {analysis['d1_clean']}")
    print(f"  d2 clean         : {analysis['d2_clean']}")
    print(f"  d3 clean         : {analysis['d3_clean']}")
    print(f"  NO FALSE POSITIVE (all detectors clean): {ok}")
    out = Path(__file__).resolve().parents[3] / "evidence" / "negative-control.json"
    out.write_text(json.dumps(record, indent=2, sort_keys=True))
    print(f"\nreceipt: {record['receipt']}\nwrote {out}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
