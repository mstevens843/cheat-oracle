# 11 - Blocking gate, stronger isolation, Arm B verifier, and transform prototype

Working record. This entry follows `results/10`: the next pass implemented hardening that is useful
locally without claiming infrastructure the current Docker Desktop LinuxKit substrate cannot
provide.

## Commands Run

```
uv run pytest
uv run ruff check .
uv run mypy
uv run python -m cheat_oracle.model
uv run python -m cheat_oracle.report --dry
docker version
docker info
docker build -f images/monitor/Dockerfile -t cheat-oracle/monitor:dev .
uv run python -m cheat_oracle.harness.blocking_demo
uv run python -m cheat_oracle.adversaries.reflexive
uv run python -m cheat_oracle.harness.arm_b --verify-evidence evidence/arm-b.json
scripts/fetch-hvtb-traces.sh --manifest
uv run python -m cheat_oracle.transform \
  --source tests/fixtures/transform/source-task \
  --answer-key tests/fixtures/transform/answer-key.txt \
  --task-id synthetic-transform-fixture \
  --out /private/tmp/cheat-oracle-transform-demo --force
uv run python -m cheat_oracle.harness.full_matrix
uv run python -m cheat_oracle.harness.negative_control
```

## Results

- Baseline before this pass: 147 tests, ruff clean, mypy clean.
- Expected suite size after this entry: 159 tests.
- Blocking mode is implemented behind `BLOCK=1`. The monitor attempts
  `FAN_OPEN_PERM | FAN_ACCESS_PERM`, denies attributed key/object-store permission events, records
  denied attempts to the same ledger, and uses the existing ledger certifier for the final verdict.
- Local blocking demonstration: GATED. Docker Desktop LinuxKit returned
  `fanotify_mark permission events unsupported errno=22`, so `blocking_demo` wrote no evidence.
- Deterministic integrity path: `tests/test_permissions.py` proves permission decisions,
  unsupported-kernel GATED classification, and overflow/malformed-event integrity failures routing
  to VOID through `certify_verdict`.
- Stronger local isolation: `cheat_oracle.adversaries.reflexive` now starts a live monitor and shows
  the subject-shaped container cannot see `/ledger`, cannot write ledger or verdict files, cannot
  see `/opt/monitor.py` in its PID namespace, and cannot enumerate monitor fds. This remains
  namespace/volume isolation only.
- Arm B verifier: `uv run python -m cheat_oracle.harness.arm_b --verify-evidence evidence/arm-b.json`
  re-derived the receipt and checked aggregates, scan parameters, the positive control, and the
  unscored denominator locally without Harbor.
- Transform: `cheat_oracle.transform` now implements a synthetic-fixture transform prototype that
  copies a source task, injects `admin/key.txt`, adds HVTB-style detector scripts, and emits
  provenance metadata. It is not a full Terminal-Bench 2.1 corpus transform.
- Monitor-dependent Docker evidence rerun after the monitor image rebuild:
  `evidence/observed-matrix.json` receipt
  `co1_1b00d2a218c01db14a71f371083769271ffe9fdd5d956c289fc1efc6a6e7fda0`.
- Negative-control evidence rerun after the monitor image rebuild; receipt remained
  `co1_36092bc8a3b6419bebb1b9cf3472d5efff1ec3a4e215f92e515596bc86551343`.

## Remaining Limits

- Blocking is implemented and feature-detected, but not demonstrated as denial-before-obtainment on
  this LinuxKit substrate. A kernel with `CONFIG_FANOTIFY_ACCESS_PERMISSIONS` is still required.
- Isolation is namespace/volume isolation inside the Docker Desktop LinuxKit VM, not separate-host
  isolation.
- c08 empirical queue-overflow reproduction remains substrate-dependent.
- Arm B remains a command-level lower-bound scan with a Harbor dependency for redownloading traces.
- No external upstream fork/PR was created.
- The transform is a synthetic-fixture prototype, not a full Terminal-Bench 2.1 transform.
