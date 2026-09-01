# Upstream Readiness

This repository is a license-clean reproduction and measurement harness, not a fork of
`MajoRoth/hack-verifiable-terminal-bench-2`. A pull request cannot be opened directly from this
repository to that one, and no pull request is required for `cheat-oracle` to be complete as a
standalone research artifact.

Checked on 2026-09-01 with GitHub's API:

- upstream: `https://github.com/MajoRoth/hack-verifiable-terminal-bench-2`
- default branch: `main`
- archived: `false`
- visible detector surface in the public prototype: `vulnerable-secret/tests/test.sh`

The public prototype's verifier scores answer-key access fail-open by checking for
`/tmp/solution_access.log` and grepping for `ACCESS|OPEN`. A missing log becomes clean. If an
external contribution is desired, the patch should be developed in a fork of the upstream
repository, or in the private/full task-transform source if that is where the detector is generated.

## Patch Scope

1. Fail closed when detector evidence is absent or suspect: missing log, empty log, lost watch, or
   overflow should void the trial.
2. Move answer-key access detection out of the subject's reachable namespace where the runner
   supports it.
3. Use superblock scope rather than an out-of-container mount mark for sidecar observation.
   `cheat-oracle` also has a feature-detected `BLOCK=1` permission-event mode, but the local
   LinuxKit substrate gates it; upstream should only claim blocking after running on a kernel with
   `CONFIG_FANOTIFY_ACCESS_PERMISSIONS`.
4. Preserve the floor: content duplicates, public network copies, and raw block-device reads need
   withholding, uniqueness, and device denial rather than object-watch detection.

## Not Done Here

No fork was created, no cross-repo patch was staged, and no upstream PR was opened. This file only
records the boundary and the patch plan so the local reproduction does not overclaim upstream
delivery.
