# 09 - Docker digest pinning and final boundary audit

Working record. This entry follows `results/08`: Docker registry access and the local Docker daemon
were available in the resumed pass. Base-image digest pinning was completed, images were rebuilt,
and the receipted Docker evidence was regenerated against the hardened monitor path.

## Docker status

Commands run:

```
docker version
docker info
docker buildx imagetools inspect debian:bookworm-slim
docker buildx imagetools inspect python:3.12.13-slim-bookworm
docker build --build-arg GUID=$(cat images/subject/harness/GUID) -t cheat-oracle/subject:dev images/subject
docker build -f images/monitor/Dockerfile -t cheat-oracle/monitor:dev .
docker build -t cheat-oracle/floor:dev images/floor
uv run python -m cheat_oracle.report
uv run python -m cheat_oracle.harness.full_matrix
uv run python -m cheat_oracle.harness.negative_control
uv run python -m cheat_oracle.harness.floor_c13
uv run python -m cheat_oracle.adversaries.reflexive
```

Result:

- Docker CLI and daemon: present, Docker Desktop 29.3.1, LinuxKit 6.12.76-linuxkit aarch64.
- `debian:bookworm-slim` manifest-list digest resolved:
  `sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171`.
- `python:3.12.13-slim-bookworm` manifest-list digest resolved:
  `sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2`.
- The subject, monitor, and floor images rebuilt successfully from those pins.
- `cheat_oracle.report` regenerated `evidence/arm-a-d0.json` with receipt
  `co1_7a1c35daa24b63afb93a0fd3f580bf5e07bf8f05281b1e82acff1d984bae8046`.
- `cheat_oracle.harness.full_matrix` regenerated `evidence/observed-matrix.json` with receipt
  `co1_2b2b8b07e63fdebd82af33c3d2ce78c7e723ef6ad732587d79453f0b34a5ff2b`; sidecar rows now carry
  the monitor's `ledger_verify` audit.
- `cheat_oracle.harness.negative_control` regenerated `evidence/negative-control.json` with receipt
  `co1_36092bc8a3b6419bebb1b9cf3472d5efff1ec3a4e215f92e515596bc86551343`.
- `cheat_oracle.harness.floor_c13` regenerated `evidence/floor-c13.json` with receipt
  `co1_c7db3d49c6cbc083cfc28e2d522d880f22b3ce81f6e2dc8afbd420dd09cc8ffc`.
- `cheat_oracle.adversaries.reflexive` passed through the real monitor-certifier path: the ledger is
  out of reach, an intact c01 ledger certifies as FIRE, and an edited ledger certifies as VOID.

`images/subject/Dockerfile`, `images/floor/Dockerfile`, and `images/monitor/Dockerfile` now pin
those manifest-list digests. `tests/test_dockerfiles.py` guards both the digest-pinning shape and
the exact digests recorded here.

Expected suite size after this entry before the Arm B denominator correction: 146 tests.

## Boundary audit

- Docker evidence was regenerated after the monitor-certification hardening. `uv run python -m
  cheat_oracle.report` still exits non-zero and withholds evidence if Docker becomes unavailable
  rather than writing ambiguous results.
- Blocking remains substrate-gated and unimplemented here. `results/00` measured that this LinuxKit
  kernel lacks `CONFIG_FANOTIFY_ACCESS_PERMISSIONS`; a real blocker would need `FAN_ACCESS_PERM`
  plus allow/deny responses on a kernel that supports permission events. The current canary-mint
  claim is observation and recording, not denial.
- Isolation remains namespace/volume isolation inside Docker Desktop's LinuxKit VM, not
  separate-machine isolation.
- c08 remains the documented substrate disagreement: the overflow mechanism is modeled, and
  fail-closed detectors VOID it, but this substrate has not reliably reproduced dropping the key
  event.
- Arm B remains a conservative lower-bound command-trace scan with an external Harbor dependency
  for redownloading the released traces.
- `transform/` remains documentation only and is not part of any headline claim.
- No external HVTB prototype PR was opened. That is optional for disclosure/contribution, not a
  requirement for `cheat-oracle` as a standalone reproduction.
