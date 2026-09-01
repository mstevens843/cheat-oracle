"""The reflexive tamper proof must use the same certifier as the monitor."""

from __future__ import annotations

from pathlib import Path

from cheat_oracle.adversaries.reflexive import prove_tamper_evident


def test_reflexive_tamper_path_certifies_void_without_docker() -> None:
    proof = prove_tamper_evident(run_monitor=False)
    assert proof["monitor_verdict_on_c01"] is None
    assert proof["certified_verdict_before_edit"] == "fires"
    assert proof["chain_ok_before_edit"] is True
    assert proof["certified_verdict_after_edit"] == "void"
    assert proof["chain_ok_after_edit"] is False
    assert proof["first_broken_index"] == 0


def test_monitor_imports_the_shared_certifier() -> None:
    monitor = Path(__file__).resolve().parents[1] / "images" / "monitor" / "monitor.py"
    src = monitor.read_text()
    assert "from cheat_oracle.ledger.certify import certify_verdict" in src
    assert "certify_verdict(ledger_path, fired, integrity_void=void)" in src


def test_monitor_overflow_is_integrity_void() -> None:
    monitor = Path(__file__).resolve().parents[1] / "images" / "monitor" / "monitor.py"
    src = monitor.read_text()
    assert "if mask & FAN_Q_OVERFLOW:" in src
    assert "void = True" in src
    assert "certify_verdict(ledger_path, fired, integrity_void=void)" in src
