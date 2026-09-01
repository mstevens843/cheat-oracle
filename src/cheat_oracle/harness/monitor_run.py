"""Orchestrate one out-of-container detector measurement for a channel: fresh volumes, populate the
shared app, start the monitor sidecar (d2 mount-mark or d3 superblock-mark), run the channel against
the shared volume, and collect the sidecar verdict beside the in-container d0 and d1 from one run.

Impure by nature (it drives docker) and never imported by the model. The subject mounts the app
volume read-write and a /ctl handshake volume; the monitor mounts the app read-only (it observes, it
does not act), the same /ctl, and its own /ledger volume the subject never mounts - the ledger is
out of the subject's reach by construction, which is the whole point of the fix.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field

SUBJECT = "cheat-oracle/subject:dev"
MONITOR = "cheat-oracle/monitor:dev"

PRIV_CHANNELS: dict[str, list[str]] = {
    "c06": ["--cap-add", "SYS_ADMIN", "--security-opt", "apparmor=unconfined"],
    "c13": ["--privileged"],
}


class DockerCommandError(RuntimeError):
    def __init__(self, cmd: list[str], proc: subprocess.CompletedProcess[str]) -> None:
        tail = (proc.stderr or proc.stdout)[-400:].strip()
        super().__init__(f"{' '.join(cmd)} failed with rc={proc.returncode}: {tail}")
        self.cmd = cmd
        self.returncode = proc.returncode
        self.stderr = proc.stderr
        self.stdout = proc.stdout


@dataclass(frozen=True)
class MonitorRun:
    channel_id: str
    detector: str                       # d2 | d3
    mode: str                           # observe | block
    d0: str | None                      # obtained-gated verdict for the matrix (fires|misses|None)
    d1: str | None
    sidecar: str | None                 # the d2/d3 verdict: fires | misses | void | error | None
    obtained: bool
    d0_flagged: bool = False            # raw flags, for the negative control (not obtained-gated)
    d1_flagged: bool = False
    detail: dict[str, object] = field(default_factory=dict)


def _run(cmd: list[str], timeout: float = 180.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


def _run_checked(cmd: list[str], timeout: float = 180.0) -> subprocess.CompletedProcess[str]:
    proc = _run(cmd, timeout)
    if proc.returncode != 0:
        raise DockerCommandError(cmd, proc)
    return proc


def _vol_create(name: str) -> None:
    _run_checked(["docker", "volume", "create", name])


def _vol_rm(name: str) -> None:
    _run(["docker", "volume", "rm", "-f", name])


def _extract_sidecar(logs: str) -> tuple[str | None, dict[str, object]]:
    sidecar, detail = None, {}
    for line in logs.splitlines():
        if line.startswith("D3_RESULT "):
            detail = json.loads(line[len("D3_RESULT ") :])
            sidecar = str(detail.get("verdict"))
    return sidecar, detail


def run_case(channel_id: str, run_id: str, detector: str = "d3", block: bool = False) -> MonitorRun:
    mode = "block" if block else "observe"
    sfx = f"{channel_id}-{detector}-{mode}-{run_id}"
    app, ctl, led = f"co-app-{sfx}", f"co-ctl-{sfx}", f"co-led-{sfx}"
    mon = f"co-mon-{sfx}"
    for v in (app, ctl, led):
        _vol_create(v)
    try:
        # 1. populate the shared app and signal env_ready
        _run_checked(["docker", "run", "--rm", "-v", f"{app}:/app", "-v", f"{ctl}:/ctl",
                      SUBJECT, "populate"])

        # 2. start the monitor detached; wait for MON_READY
        _run(["docker", "rm", "-f", mon])
        _run_checked([
            "docker", "run", "-d", "--name", mon, "--privileged",
            "-v", f"{app}:/app:ro", "-v", f"{ctl}:/ctl", "-v", f"{led}:/ledger",
            "-e", "TIMEOUT=40", "-e", f"DETECTOR={detector}",
            *([] if not block else ["-e", "BLOCK=1"]),
            MONITOR,
        ])
        ready = False
        early_sidecar: str | None = None
        early_detail: dict[str, object] = {}
        for _ in range(80):
            logs = _run(["docker", "logs", mon]).stdout
            early_sidecar, early_detail = _extract_sidecar(logs)
            if "MON_READY" in logs:
                ready = True
                break
            if early_sidecar in {"gated", "error"}:
                return MonitorRun(
                    channel_id, detector, mode, None, None, early_sidecar, False,
                    detail=early_detail,
                )
            subprocess.run(["sleep", "0.25"], check=False)
        if not ready:
            return MonitorRun(channel_id, detector, mode, None, None, "error", False,
                              detail={"reason": "monitor not ready"})

        # 3. run the subject (a channel or clean_noop) against the shared volume
        proc = _run_checked([
            "docker", "run", "--rm", *PRIV_CHANNELS.get(channel_id, []),
            "-v", f"{app}:/app", "-v", f"{ctl}:/ctl", SUBJECT, channel_id,
        ])
        obtained = False
        d0f = d1f = False
        for line in proc.stdout.splitlines():
            if line.startswith("CASE_RESULT "):
                raw = json.loads(line[len("CASE_RESULT ") :])
                obtained = bool(raw.get("obtained"))
                d0f = bool(raw.get("d0_flagged"))
                d1f = bool(raw.get("d1_flagged"))
        d0 = "fires" if d0f else ("misses" if obtained else None)
        d1 = "fires" if d1f else ("misses" if obtained else None)

        # 4. wait for the monitor to finish and read its verdict
        _run(["docker", "wait", mon])
        mlogs = _run(["docker", "logs", mon]).stdout
        sidecar, detail = _extract_sidecar(mlogs)
        detail["subject_result"] = raw
        return MonitorRun(channel_id, detector, mode, d0, d1, sidecar, obtained,
                          d0_flagged=d0f, d1_flagged=d1f, detail=detail)
    finally:
        _run(["docker", "rm", "-f", mon])
        for v in (app, ctl, led):
            _vol_rm(v)
