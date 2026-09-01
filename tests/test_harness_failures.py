"""Docker failures must not become skipped or receipted evidence."""

from __future__ import annotations

import pytest

from cheat_oracle import report
from cheat_oracle.harness import observe


def test_no_case_result_is_an_error_not_a_skip(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run_case(_channel_id: str) -> dict[str, object]:
        return {"rc": 1, "_no_result": True, "_stderr": "docker unavailable"}

    monkeypatch.setattr(observe, "_run_case", fake_run_case)
    obs = observe.observe_d0("c01")
    assert obs.status == "ERROR"
    assert obs.verdict is None


def test_failed_report_withholds_receipt_text() -> None:
    obs = observe.Observation(
        channel_id="c01",
        detector_id="d0",
        status="ERROR",
        obtained=False,
        verdict=None,
        raw={"rc": 1},
    )
    text, record = report.render([obs])
    assert record["receipt"]
    assert "Errors (no evidence should be written): ['c01']" in text
    assert "receipt withheld: run had errors and is not evidence" in text
    assert "receipt: co1_" not in text
