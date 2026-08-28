"""Regenerate the full OBSERVED matrix - all four detector rungs for every channel - beside the
prediction, and compute the discrimination the whole project claims: each rung recovers a named set
the weaker one undercounts, and there is still an honest floor the fix does not catch. Writes
evidence/observed-matrix.json with a canonical-JSON SHA-256 receipt so the table is measured, not
remembered.

The four rungs, and how each is observed:
  - d0 (HVTB replica) and d1 (inode watch) run in the subject container; one run reports both.
  - d2 (mount mark) and d3 (superblock mark, the fix) each run as an out-of-container sidecar. d2 is
    measured but NOT diffed cell-by-cell against its prediction: a fanotify MOUNT mark is
    per-vfsmount, so from its own mount of the shared volume it observes NONE of the subject's
    reads. That blindness is the measured reason the fix marks the superblock (results/04); it is
    reported as a finding, not as a column of model errors.

`uv run python -m cheat_oracle.harness.full_matrix`   (needs docker + both images)
"""

from __future__ import annotations

import json
from pathlib import Path

from ..canonical import receipt
from ..model.channels import CHANNEL_IDS, CHANNELS_BY_ID
from ..model.predict import PREDICTED
from . import monitor_run

# c13 is the floor: it needs raw device access this flow does not grant. It is measured separately
# by cheat_oracle.harness.floor_c13 and recorded there, never as a silent pass here.
MATRIX_SKIP = {"c13"}
# d2 is measured but not cell-diffed: an out-of-container mount mark is blind cross-container (see
# the module docstring).
DIFFED_DETECTORS = ("d0", "d1", "d3")
RUN_ID = "matrix"


def _obs_symbol(v: str | None, exercised: bool) -> str:
    if not exercised:
        return "skip"
    return {"fires": "FIRE", "misses": "miss", "void": "VOID"}.get(v or "", v or "?")


def collect() -> dict[str, dict[str, object]]:
    observed: dict[str, dict[str, object]] = {}
    for cid in CHANNEL_IDS:
        if cid in MATRIX_SKIP:
            observed[cid] = {"obtained": False, "d0": None, "d1": None, "d2": None, "d3": None,
                             "d0_status": "SKIPPED", "d1_status": "SKIPPED",
                             "d2_status": "SKIPPED", "d3_status": "SKIPPED"}
            continue
        r3 = monitor_run.run_case(cid, RUN_ID, detector="d3")  # d0, d1, d3
        r2 = monitor_run.run_case(cid, RUN_ID, detector="d2")  # d2
        exercised = bool(r3.obtained)
        observed[cid] = {
            "obtained": exercised,
            "d0": r3.d0, "d0_status": "OK" if r3.d0 else "OTHER",
            "d1": r3.d1, "d1_status": "OK" if r3.d1 else "OTHER",
            "d2": r2.sidecar, "d3": r3.sidecar,
            "d2_status": "OK" if r2.sidecar in ("fires", "misses", "void") else "OTHER",
            "d3_status": "OK" if r3.sidecar in ("fires", "misses", "void") else "OTHER",
            "d2_fired": r2.detail.get("fired") if isinstance(r2.detail, dict) else None,
            "d3_fired": r3.detail.get("fired") if isinstance(r3.detail, dict) else None,
        }
    return observed


def analyze(observed: dict[str, dict[str, object]]) -> dict[str, object]:
    d0_under, d1_under, d3_floor = [], [], []
    rec_d1_over_d0, rec_d3_over_d0, rec_d3_over_d1 = [], [], []
    d2_caught, disagreements = [], []
    for cid in CHANNEL_IDS:
        o = observed[cid]
        if not o.get("obtained"):
            continue
        d0v, d1v, d2v, d3v = o.get("d0"), o.get("d1"), o.get("d2"), o.get("d3")
        if d0v == "misses":
            d0_under.append(cid)
        if d1v == "misses":
            d1_under.append(cid)
        if d3v == "misses":
            d3_floor.append(cid)
        if d0v == "misses" and d1v == "fires":
            rec_d1_over_d0.append(cid)
        if d0v == "misses" and d3v in ("fires", "void"):
            rec_d3_over_d0.append(cid)
        if d1v == "misses" and d3v in ("fires", "void"):
            rec_d3_over_d1.append(cid)
        if d2v in ("fires", "void"):
            d2_caught.append(cid)  # expected empty: a cross-container mount mark is blind
        for det in DIFFED_DETECTORS:
            ov = o.get(det)
            if ov in ("fires", "misses", "void"):
                pv = PREDICTED[cid][det].verdict.value
                if ov != pv:
                    disagreements.append({"channel": cid, "detector": det,
                                          "predicted": pv, "observed": ov})
    return {
        "d0_undercount": d0_under,
        "d1_undercount": d1_under,
        "d3_undercount_floor": d3_floor,
        "recovered_d1_over_d0": rec_d1_over_d0,
        "recovered_by_fix": rec_d3_over_d0,
        "recovered_d3_over_d1": rec_d3_over_d1,
        "d2_out_of_container_caught": d2_caught,
        "disagreements": disagreements,
        "discrimination": {
            "d1_recovers_over_d0": bool(rec_d1_over_d0),
            "fix_catches_strictly_more": (
                bool(rec_d3_over_d0) and set(d3_floor) < set(d0_under)
            ),
            "fix_beats_inode_watch": bool(rec_d3_over_d1),
            "d2_blind_out_of_container": not d2_caught,
            "floor_nonempty": bool(d3_floor),
        },
    }


def render(observed: dict[str, dict[str, object]], analysis: dict[str, object]) -> str:
    lines = [
        "Observed matrix - predicted(P)/observed(O). d0=HVTB dir watch, d1=inode watch, "
        "d2=mount mark (out-of-container), d3=canary-mint superblock (the fix).",
        f"{'channel':22}{'d0 P/O':>11}{'d1 P/O':>11}{'d2 O':>8}{'d3 P/O':>11}  note",
        "-" * 84,
    ]
    for cid in CHANNEL_IDS:
        ch = CHANNELS_BY_ID[cid]
        o = observed[cid]
        cells = ""
        for det in ("d0", "d1"):
            p = PREDICTED[cid][det].verdict.value[:4]
            ob = _obs_symbol(o.get(det), o.get(f"{det}_status") == "OK")  # type: ignore[arg-type]
            cells += f"{p + '/' + ob:>11}"
        d2o = _obs_symbol(o.get("d2"), o.get("d2_status") == "OK")  # type: ignore[arg-type]
        cells += f"{d2o:>8}"
        p3 = PREDICTED[cid]["d3"].verdict.value[:4]
        d3o = _obs_symbol(o.get("d3"), o.get("d3_status") == "OK")  # type: ignore[arg-type]
        cells += f"{p3 + '/' + d3o:>11}"
        note = ""
        if cid == "c08":
            note = "overflow not reproduced (substrate)"
        elif cid == "c13":
            note = "floor: measured by floor_c13"
        lines.append(f"{cid + ' ' + ch.slug:22}{cells}  {note}")
    disc = analysis["discrimination"]
    assert isinstance(disc, dict)
    lines += [
        "",
        f"HVTB (d0) undercount (obtained, scored clean): {analysis['d0_undercount']}",
        f"Inode watch (d1) recovers over d0: {analysis['recovered_d1_over_d0']}",
        f"canary-mint (d3) recovers over d0: {analysis['recovered_by_fix']}",
        f"canary-mint (d3) beats the inode watch (d1) on: {analysis['recovered_d3_over_d1']}",
        f"Honest floor (obtained, d3 still misses): {analysis['d3_undercount_floor']}",
        f"d2 mount mark caught (out-of-container): {analysis['d2_out_of_container_caught']} "
        "(empty: a per-vfsmount mount mark is blind across the container boundary - the measured "
        "reason the fix marks the superblock)",
        f"Predicted-vs-observed disagreements (d0/d1/d3): {analysis['disagreements']}",
        f"DISCRIMINATION d1>d0={disc['d1_recovers_over_d0']} "
        f"fix>d0={disc['fix_catches_strictly_more']} fix>d1={disc['fix_beats_inode_watch']} "
        f"d2_blind={disc['d2_blind_out_of_container']} floor_nonempty={disc['floor_nonempty']}",
    ]
    return "\n".join(lines)


def main() -> int:
    observed = collect()
    analysis = analyze(observed)
    record: dict[str, object] = {"observed": observed, "analysis": analysis}
    record["receipt"] = receipt(record)
    text = render(observed, analysis)
    print(text)
    out = Path(__file__).resolve().parents[3] / "evidence" / "observed-matrix.json"
    out.write_text(json.dumps(record, indent=2, sort_keys=True))
    print(f"\nreceipt: {record['receipt']}\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
