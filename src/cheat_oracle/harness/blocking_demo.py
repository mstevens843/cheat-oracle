"""Docker demonstration for canary-mint's optional fanotify blocking mode.

On kernels with CONFIG_FANOTIFY_ACCESS_PERMISSIONS, this proves the monitor can deny an attributed
answer-key read before bytes are obtained. On Docker Desktop LinuxKit, the expected result is GATED:
the monitor attempts permission events, the kernel rejects them, and no evidence is written.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..canonical import receipt
from . import monitor_run

_ROOT = Path(__file__).resolve().parents[3]


def _run_summary(run: monitor_run.MonitorRun) -> dict[str, object]:
    subject = run.detail.get("subject_result") if isinstance(run.detail, dict) else None
    return {
        "channel": run.channel_id,
        "detector": run.detector,
        "mode": run.mode,
        "sidecar": run.sidecar,
        "obtained": run.obtained,
        "subject_rc": dict(subject).get("rc") if isinstance(subject, dict) else None,
        "ledger_verify": run.detail.get("ledger_verify") if isinstance(run.detail, dict) else None,
        "fired": run.detail.get("fired") if isinstance(run.detail, dict) else None,
        "reason": run.detail.get("reason") if isinstance(run.detail, dict) else None,
    }


def run_demo(run_id: str = "block") -> dict[str, object]:
    clean = monitor_run.run_case("clean_noop", run_id=run_id, detector="d3", block=True)
    if clean.sidecar == "gated":
        return {
            "status": "GATED",
            "reason": clean.detail.get("reason"),
            "kernel_supported": False,
            "evidence_written": False,
            "clean": _run_summary(clean),
        }

    if clean.sidecar != "misses":
        return {
            "status": "FAIL",
            "reason": "clean workload was not allowed cleanly",
            "kernel_supported": True,
            "evidence_written": False,
            "clean": _run_summary(clean),
        }

    denied = monitor_run.run_case("c01", run_id=run_id, detector="d3", block=True)
    record: dict[str, object] = {
        "status": "OK",
        "kernel_supported": True,
        "clean": _run_summary(clean),
        "denied_read": _run_summary(denied),
    }
    ledger = denied.detail.get("ledger_verify") if isinstance(denied.detail, dict) else None
    ledger_ok = isinstance(ledger, dict) and ledger.get("ok") is True
    fired = denied.detail.get("fired") if isinstance(denied.detail, dict) else None
    key_hits = dict(fired).get("key") if isinstance(fired, dict) else 0
    subject = denied.detail.get("subject_result") if isinstance(denied.detail, dict) else None
    subject_rc = dict(subject).get("rc") if isinstance(subject, dict) else 0
    demonstrated = (
        clean.sidecar == "misses"
        and denied.sidecar == "fires"
        and denied.obtained is False
        and isinstance(subject_rc, int)
        and subject_rc != 0
        and isinstance(key_hits, int)
        and key_hits > 0
        and ledger_ok
    )
    record["blocking_demonstrated"] = demonstrated
    record["evidence_written"] = False
    if not demonstrated:
        record["status"] = "FAIL"
        record["reason"] = "blocking invariants did not hold"
    return record


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", default="block")
    ap.add_argument("--out", default=str(_ROOT / "evidence" / "blocking-demo.json"))
    args = ap.parse_args(argv)

    try:
        record = run_demo(args.run_id)
    except monitor_run.DockerCommandError as exc:
        print(f"blocking demo failed before evidence was produced: {exc}")
        return 1

    print(json.dumps(record, indent=2, sort_keys=True))
    if record["status"] == "GATED":
        print("\nBLOCKING DEMO GATED: kernel does not support fanotify permission events.")
        print("No evidence written.")
        return 0
    if record["status"] != "OK":
        print("\nBLOCKING DEMO FAIL: no evidence written.")
        return 1

    out = Path(args.out)
    record["evidence_written"] = True
    record["receipt"] = receipt(record)
    out.write_text(json.dumps(record, indent=2, sort_keys=True))
    print(f"\nBLOCKING DEMO PASS: wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
