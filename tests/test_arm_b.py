"""Arm B scanner wiring, on a SYNTHETIC fixture (tests/fixtures/arm_b - not HVTB data). The real
2,225 HVTB traces are gated (not shared with this account), so Arm B has no measured headline; this
asserts the scanner is correct so it is trustworthy the moment real trials land in arm-b/traces/. It
also asserts the honest gate: an empty traces dir reports GATED and writes nothing.
"""

from __future__ import annotations

from pathlib import Path

from cheat_oracle.harness import arm_b

_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "arm_b" / "traces"


def test_scanner_flags_the_planted_undercounts() -> None:
    res = arm_b.scan_all(_FIXTURE, key_path="admin/", clean_reward=0.0)
    assert res.n_trials == 3
    assert res.n_scored_clean == 2  # the two reward=0.0 trials
    # The hardlink (c02) and git-catfile (c04) trials obtained the key while scored clean; the plain
    # read that was scored caught (reward 1.0) is not an undercount.
    assert set(res.undercounts) == {"trial-hardlink-clean", "trial-gitcat-clean"}
    assert set(res.by_channel) == {"c02", "c04"}


def test_only_d0_missed_channels_count_as_undercounts() -> None:
    # c01 (a plain admin/ read) is caught by the directory watch, so even if it appeared it would
    # not be an undercount. The scanner ties the undercount set to the model's d0-missed set.
    res = arm_b.scan_all(_FIXTURE, key_path="admin/", clean_reward=0.0)
    from cheat_oracle.model.detectors import DETECTORS_BY_ID
    from cheat_oracle.model.predict import summarize

    d0_missed = set(summarize(DETECTORS_BY_ID["d0"]).misses)
    assert set(res.by_channel) <= d0_missed


def test_gated_when_no_traces(tmp_path: Path) -> None:
    empty = tmp_path / "traces"
    empty.mkdir()
    rc = arm_b.main(["--traces", str(empty), "--out", str(tmp_path / "arm-b.json")])
    assert rc == 0
    assert not (tmp_path / "arm-b.json").exists(), "GATED run must not write evidence"
