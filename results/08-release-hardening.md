# 08 - Release hardening: certify the ledger, tighten the boundary

Working record. No Docker evidence was regenerated in this pass: Docker was not running in the
workspace (`docker image inspect` could not connect to the socket). The committed receipted evidence
was verified by the test suite, and the changes here are host-testable code, docs, and harness
failure behavior.

2026-09-01 follow-up: the Docker digest-pinning and Docker evidence-rerun status in this entry are
superseded by `results/09-digest-pinning.md`; the Arm B denominator is superseded by
`results/10-arm-b-rerun-correction.md`.

## What changed

- `src/cheat_oracle/ledger/certify.py` now owns final verdict certification for canary-mint. A FIRE
  is certifiable only when the ledger hash chain verifies and has exactly one record per attributed
  event the monitor counted in memory.
- `images/monitor/monitor.py` imports that certifier and includes `ledger_verify` in its emitted
  `D3_RESULT`/`verdict.json`. Missing, malformed, edited, extra, or truncated ledger records now
  produce VOID rather than a clean pass.
- `src/cheat_oracle/adversaries/reflexive.py` calls the same certifier for the tamper proof. The
  out-of-reach proof still needs Docker because it demonstrates the subject's mounted namespace.
- `src/cheat_oracle/harness/observe.py`, `monitor_run.py`, `full_matrix.py`, and
  `negative_control.py` now fail before writing evidence when required Docker commands fail or
  produce no trustworthy verdict. Intentional GATED flows still write no evidence.
- The unused `pynacl` optional extra was removed. The hash-chain threat model here is integrity of
  the monitor-owned ledger, not third-party signature verification; adding signatures without
  key-management would not improve the claim.
- Docker base tags were tightened from floating `stable`/minor tags to release-pinned tags:
  `debian:bookworm-slim` and `python:3.12.13-slim-bookworm`. They are still not digest-pinned,
  because Docker image inspection/builds could not be run here.
- `DISCLOSURE.md` is now a ready-to-send disclosure, and `UPSTREAM.md` records the inspected
  upstream boundary. This repo is not a fork of `MajoRoth/hack-verifiable-terminal-bench-2`, so no
  direct PR was opened.
- `transform/README.md` records that the provenance transform is intentionally not implemented and
  is not part of any headline claim.

## Checks

Host-testable checks run in this pass:

```
uv run pytest
uv run ruff check .
uv run mypy
uv run python -m cheat_oracle.model
uv run python -m cheat_oracle.report --dry
uv run python -m cheat_oracle.harness.arm_b --traces /private/tmp/nonexistent-cheat-oracle-traces
```

Expected suite size after this entry: 141 tests. The new tests are
`tests/test_ledger_certify.py`, `tests/test_reflexive_certification.py`, and
`tests/test_harness_failures.py`.

Still not done at this point, unchanged and stated: blocking on a kernel with
`CONFIG_FANOTIFY_ACCESS_PERMISSIONS`, separate-machine isolation, reliable c08 queue-overflow
reproduction on this substrate, Harbor trace redownload without the external Harbor dependency,
Docker evidence remeasurement, an optional external upstream PR, and the Terminal-Bench -> HVTB-form
transform. Docker digest pinning is completed in `results/09`.
