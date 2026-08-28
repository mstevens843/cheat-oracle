"""THE GUARDS, ATTACKED - AS A TEST RATHER THAN AS A STORY.

The three evidence guards (test_arm_a, test_arm_b_evidence, test_floor) and the two older ones exist
to make a hand-edited number turn the suite red. That property was originally established by editing
`evidence/` by hand twelve times and watching pytest fail, which proved it once, on one machine, and
left nothing anyone else could run. A claim about rigour that cannot be re-run is the exact thing
this repo refuses to accept from HVTB, so it should not accept it here either.

This runs the audit, against the threat model that actually matters. A receipt only catches a NAIVE
edit: the canonicalization is in this repo, so anyone changing a number can recompute a valid
receipt in one line. So every mutation here is RESEALED - the record is corrupted and then given a
correct receipt - which means the receipt check passes and only the CLAIM assertions can catch it.
That is the honest test of whether the guards guard anything. (One mutation forges the receipt
instead, to prove the receipt check itself is live.)

For each row it copies the real artifact, corrupts one published number, reseals, points the guard
module at the copy, and requires that at least one of that module's assertions still fails.

It also pins the artifacts as REQUIRED. Every guard skips when its file is missing, so deleting
`evidence/` would otherwise turn the suite green by silence.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

import tests.test_arm_a as guard_arm_a
import tests.test_arm_b_evidence as guard_arm_b
import tests.test_discrimination as guard_matrix
import tests.test_floor as guard_floor
import tests.test_negative_controls as guard_negative
from cheat_oracle.canonical import receipt

EVIDENCE_DIR = Path(__file__).resolve().parent.parent / "evidence"

# Every receipted artifact, and the guard module that must refuse to certify a rewritten copy.
GUARDED: list[tuple[str, ModuleType]] = [
    ("arm-a-d0.json", guard_arm_a),
    ("arm-b.json", guard_arm_b),
    ("floor-c13.json", guard_floor),
    ("observed-matrix.json", guard_matrix),
    ("negative-control.json", guard_negative),
]

# (artifact, label, mutate, reseal). reseal=True recomputes a valid receipt after the edit, so the
# receipt check cannot be what catches it.
Mutation = tuple[str, str, Callable[[dict[str, Any]], None], bool]


def _drop_positive_control(rec: dict[str, Any]) -> None:
    for scan in rec["scans"]:
        scan["obtained_via"] = []


def _truncate_corpus(rec: dict[str, Any]) -> None:
    rec["scans"] = rec["scans"][:2000]
    rec["n_trials"] = 2000


def _unobtain_c03(rec: dict[str, Any]) -> None:
    for row in rec["rows"]:
        if row["channel"] == "c03":
            row["obtained"] = False


# One published number per row, edited the way someone flattering the result would edit it.
MUTATIONS: list[Mutation] = [
    ("arm-a-d0.json", "drop c12 from the undercount (7 -> 6)",
     lambda r: r["undercount_channels"].remove("c12"), True),
    ("arm-a-d0.json", "inflate the undercount to 8",
     lambda r: r["undercount_channels"].append("c06"), True),
    ("arm-a-d0.json", "count c03 that never obtained the key", _unobtain_c03, True),
    ("arm-a-d0.json", "erase the predicted-vs-observed disagreements",
     lambda r: r.__setitem__("disagreements", []), True),
    ("arm-a-d0.json", "forge the receipt",
     lambda r: r.__setitem__("receipt", "co1_" + "0" * 64), False),
    ("arm-b.json", "invent 12 retroactive undercounts",
     lambda r: r.update(n_undercounts=12, undercounts=["t"] * 12), True),
    ("arm-b.json", "move the clean-scored denominator",
     lambda r: r.__setitem__("n_scored_clean", 1500), True),
    ("arm-b.json", "swap the scored field to the task reward",
     lambda r: r.__setitem__("score_field", "reward"), True),
    ("arm-b.json", "delete the positive control", _drop_positive_control, True),
    ("arm-b.json", "truncate the corpus", _truncate_corpus, True),
    ("floor-c13.json", "kill the VFS positive control",
     lambda r: r["probe"].__setitem__("fanotify_fired_on_vfs_read", False), True),
    ("floor-c13.json", "claim the raw read obtained nothing",
     lambda r: r["probe"].__setitem__("obtained_via_raw_device", False), True),
    ("floor-c13.json", "mark the probe gated",
     lambda r: r["probe"].__setitem__("gated", True), True),
    ("observed-matrix.json", "erase the model-vs-observation disagreements",
     lambda r: r["analysis"].__setitem__("disagreements", []), True),
    ("observed-matrix.json", "claim the fix recovered every channel",
     lambda r: r["analysis"].__setitem__(
         "recovered_by_fix", sorted(r["observed"])), True),
    ("observed-matrix.json", "empty the honest floor the fix does not close",
     lambda r: r["analysis"].__setitem__("d3_undercount_floor", []), True),
    ("observed-matrix.json", "widen the d0 undercount to inflate the headline",
     lambda r: r["analysis"].__setitem__(
         "d0_undercount", sorted(set(r["analysis"]["d0_undercount"]) | {"c01"})), True),
    ("negative-control.json", "hide a false positive in the summary",
     lambda r: r["analysis"].__setitem__("d3_clean", False), True),
    ("negative-control.json", "hide a d3 false positive in the run beneath the summary",
     lambda r: r["observed"].__setitem__("d3", "fires"), True),
    ("negative-control.json", "swap in a subject that was never the benign one",
     lambda r: r["observed"].__setitem__("subject", "c01_worktree_read"), True),
]

_MODULE_BY_ARTIFACT = dict(GUARDED)


def _guard_tests(module: ModuleType) -> list[Callable[[], None]]:
    fns = [v for k, v in vars(module).items() if k.startswith("test_") and callable(v)]
    assert fns, f"{module.__name__} exposes no test functions to run"
    return fns


@pytest.mark.parametrize("artifact,_module", GUARDED, ids=[a for a, _ in GUARDED])
def test_every_receipted_artifact_is_committed(artifact: str, _module: ModuleType) -> None:
    # Each guard skips when its file is absent so a docker-less machine is honest rather than red.
    # That is only safe while something REQUIRES the committed artifacts to exist; this is it.
    path = EVIDENCE_DIR / artifact
    assert path.exists(), (
        f"evidence/{artifact} is missing; its guard would skip and green the suite"
    )
    rec = json.loads(path.read_text())
    assert isinstance(rec, dict) and rec.get("receipt"), f"evidence/{artifact} carries no receipt"


@pytest.mark.parametrize("artifact,label,mutate,reseal", MUTATIONS,
                         ids=[f"{a.split('.')[0]}-{lbl}" for a, lbl, _, _ in MUTATIONS])
def test_a_resealed_hand_edit_still_turns_the_suite_red(
    artifact: str, label: str, mutate: Callable[[dict[str, Any]], None], reseal: bool,
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = EVIDENCE_DIR / artifact
    if not source.exists():
        pytest.skip(f"evidence/{artifact} absent")
    record: dict[str, Any] = json.loads(source.read_text())
    mutate(record)
    if reseal:
        # Recompute a VALID receipt over the corrupted record, exactly as an editor with this repo
        # in front of them would. The receipt check now passes; only the claims can object.
        record.pop("receipt", None)
        record["receipt"] = receipt(record)

    forged = tmp_path / artifact
    forged.write_text(json.dumps(record, indent=2, sort_keys=True))

    module = _MODULE_BY_ARTIFACT[artifact]
    monkeypatch.setattr(module, "EVIDENCE", forged)

    failures = 0
    for fn in _guard_tests(module):
        try:
            fn()
        except AssertionError:
            failures += 1
        except (KeyError, IndexError, TypeError):
            # A mutation that breaks the shape is also a rejection, just a blunter one.
            failures += 1
    sealed = "resealed with a valid receipt" if reseal else "with a forged receipt"
    assert failures, (
        f"{module.__name__} accepted evidence/{artifact} with '{label}' applied ({sealed}): "
        "the guard does not actually guard this number"
    )


def test_the_unmutated_artifacts_still_pass_their_own_guards() -> None:
    # The control for the audit above: if the guards rejected everything, the mutation test would
    # pass for the wrong reason and prove nothing.
    for _artifact, module in GUARDED:
        for fn in _guard_tests(module):
            fn()
