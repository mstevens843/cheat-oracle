"""Fill the observed column beside each predicted one, by running the real channel programs in real
containers against the HVTB replica (d0).

This is the measurement half. It shells out to docker - so it is impure by nature and lives well
outside the model. Its whole job is to try to prove the prediction wrong: for each channel it runs
a fresh container, reads whether the channel obtained the key (the canary GUID appeared) and whether
the fail-open verifier flagged it, and turns that into an observed Verdict that the report then
diffs against predict.PREDICTED. A disagreement is a finding, and the report is built to show it
rather than smooth it over.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass

from cheat_oracle.model.channels import CHANNEL_IDS
from cheat_oracle.model.layers import Verdict

SUBJECT_IMAGE = "cheat-oracle/subject:dev"

# Channels that need capabilities an ordinary sandbox denies. Recorded so a SKIP is explicit and a
# privileged run is never silently assumed.
PRIV_CHANNELS: dict[str, list[str]] = {
    "c06": ["--cap-add", "SYS_ADMIN", "--security-opt", "apparmor=unconfined"],
    "c13": ["--privileged"],
}

# Exit codes a channel uses to say "I could not be exercised here" rather than "I ran and failed".
_SKIP_RCS = {3, 4, 5}


@dataclass(frozen=True)
class Observation:
    channel_id: str
    detector_id: str
    status: str          # OK | SKIPPED | ERROR
    obtained: bool
    verdict: Verdict | None
    raw: dict[str, object]


def _run_case(
    channel_id: str, image: str = SUBJECT_IMAGE, timeout: float = 120.0
) -> dict[str, object]:
    cmd = ["docker", "run", "--rm", *PRIV_CHANNELS.get(channel_id, []), image, channel_id]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    for line in proc.stdout.splitlines():
        if line.startswith("CASE_RESULT "):
            return dict(json.loads(line[len("CASE_RESULT ") :]))
    return {"channel": channel_id, "obtained": False, "d0_flagged": False, "rc": proc.returncode,
            "_no_result": True, "_stderr": proc.stderr[-400:]}


def observe_d0(channel_id: str) -> Observation:
    raw = _run_case(channel_id)
    rc_val = raw.get("rc", -1)
    rc = rc_val if isinstance(rc_val, int) else -1
    obtained = bool(raw.get("obtained", False))
    flagged = bool(raw.get("d0_flagged", False))
    if raw.get("_no_result") or rc in _SKIP_RCS:
        return Observation(channel_id, "d0", "SKIPPED", obtained, None, raw)
    if not obtained:
        return Observation(channel_id, "d0", "ERROR", obtained, None, raw)
    # d0 is fail-open: it either flagged (FIRES) or it did not (MISSES). It never voids.
    verdict = Verdict.FIRES if flagged else Verdict.MISSES
    return Observation(channel_id, "d0", "OK", obtained, verdict, raw)


def observe_all_d0(channel_ids: tuple[str, ...] = CHANNEL_IDS) -> list[Observation]:
    return [observe_d0(cid) for cid in channel_ids]
