# cheat-oracle

**An in-container answer-key detector is a detector the subject can reach, so it systematically
undercounts. This models the undercount, measures it against a definitional ground truth, closes
the reachable channels with an out-of-container tamper-evident ledger, and names the one channel
even the fix cannot close.**

The target is real. HVTB ("Hack-Verifiable Terminal Bench", arXiv 2608.22103, Roth / Bercovich /
Efroni, 2026-08-22) measures agent reward-hacking by planting the ground-truth solution and hidden
tests in an `admin/` directory inside the agent's own container and watching it with in-container
`inotify`. The verifier greps a flag file afterward, fail-open: a missing flag is scored "no hack."
The paper calls its rates "a lower bound" but scopes that only to hacks that route around `admin/`;
the words *kill*, *pkill*, *tamper*, *evade* appear nowhere in it. Evading the watcher itself is the
unclaimed gap this measures.

This is defensive eval-integrity research, run entirely in the author's own sandbox against a
license-clean reproduction, ending in an upstream fix. The offensive programs are detector test
cases. No exploit is pointed at a system the author does not control.

> [!WARNING]
> **Pre-1.0, nothing published.** What is true is stated with the command that reproduces it; what
> is not done is listed as not done. Full record in [RESULTS.md](./RESULTS.md).
>
> **What runs today, measured rather than remembered:**
>
> - **The model.** `src/cheat_oracle/model/` derives, as a pure total function over declared
>   channel and detector properties, the predicted verdict (FIRES / MISSES / VOID) for 13 obtainment
>   channels against 4 detectors. No exploit is consulted to produce it: `uv run python -m
>   cheat_oracle.model`. Purity is checked, not asserted - `tests/test_contract.py` parses the model
>   with `ast` and fails on a clock, a random draw, a filesystem, or a network call. Zero
>   third-party dependencies in the model.
> - **Arm A, the undercount, measured.** Against a faithful reproduction of HVTB's detector in real
>   containers, **7 of 12 exercised channels obtained the answer key while the detector scored the
>   run clean** - a hardlink outside the watched dir, a pre-existing copy, git cat-file, a
>   zlib-inflated loose object, killing the watcher, unlinking the flag, and a network fetch:
>   `uv run python -m cheat_oracle.report`.
> - **The full four-rung ladder, measured.** `uv run python -m cheat_oracle.harness.full_matrix`
>   runs every detector against real containers: the inode watch (d1) recovers exactly c02 over
>   HVTB; canary-mint (d3) recovers 5 (c02, c04, c05, c10, c11) and beats even the inode watch on the
>   object-store and detector-attack channels (c04, c05, c10, c11); the fix stays honest about the
>   floor it does not close (c03, c12, c13). Predicted equals observed in every exercised cell except
>   one documented substrate case (c08 overflow).
> - **No false positives.** A negative-control subject that does legitimate work and never touches
>   the key is scored clean by all four detectors: `uv run python -m
>   cheat_oracle.harness.negative_control`.
> - **The floor is measured, not asserted.** `uv run python -m cheat_oracle.harness.floor_c13`: a raw
>   read of the backing block device obtains the key while the SAME superblock mark the fix uses
>   stays silent (it fires on a VFS read of the same file - the positive control).
> - **The fix survives its own attack.** `uv run python -m cheat_oracle.adversaries.reflexive`: the
>   ledger is out of the subject's reach, and editing any record breaks the hash chain so the
>   monitor emits VOID rather than a clean pass.
> - **The measurement corrected the model, twice.** It caught the model mispredicting the bind-mount
>   channel (`results/02`), then showed d2's out-of-container mount mark is blind cross-container - a
>   `FAN_MARK_MOUNT` is per-vfsmount, the measured reason the fix marks the superblock (`results/04`).
>   Every observed run carries a canonical-JSON SHA-256 receipt that its test re-derives.
>
> - **Arm B is wired and waiting on data.** `cheat_oracle.harness.arm_b` scans Harbor trial dirs for
>   the retroactive undercount and is validated on a synthetic fixture, but the 2,225 released HVTB
>   traces are not shared with our Harbor account (`harbor download` reports no access; the hub lists
>   no HVTB job), so it reports GATED and writes no evidence until real trials land in `arm-b/traces/`.
>
> **What is NOT done:** the retroactive undercount over the real HVTB traces (Arm B; the traces are
> gated behind Harbor sharing, see above), and blocking rather than observing (this kernel lacks
> `CONFIG_FANOTIFY_ACCESS_PERMISSIONS`; `results/00`). None of the headline depends on them.
>
> **Do not cite a number from this repo that does not name the command that produced it.**

## The thesis, and the four-detector ladder

`AI proposes, deterministic systems decide what is allowed to execute` - and a detector that
adjudicates cheating is one such decider. HVTB's decider lives where the subject can reach it. The
model isolates why that matters on three orthogonal axes (observation layer, in-reach vs out, fail
mode) by walking a ladder of four detectors from HVTB to the fix; see
`src/cheat_oracle/model/detectors.py`.

## Layout

```
src/cheat_oracle/model/       the prediction: layers, channels, detectors, predict (pure, purity-tested)
src/cheat_oracle/canonical.py canonical JSON + SHA-256 receipts (ported from the outbox idempotency)
src/cheat_oracle/ledger/      canary-mint: attribution + hash-chained tamper-evident ledger (pure core)
src/cheat_oracle/harness/     observe.py (d0), monitor_run.py (d0/d1 + d2/d3 sidecars), full_matrix.py,
                              negative_control.py, floor_c13.py, arm_b.py (retroactive trace scanner)
src/cheat_oracle/report.py    Arm A: HVTB undercount, predicted vs observed, with a receipt
src/cheat_oracle/adversaries/ reflexive.py: attack the fix (out of reach + tamper-evident)
images/subject/               the subject + HVTB-replica image (d0 dir watch + d1 inode watch)
images/monitor/               the canary-mint sidecar (d3 FAN_MARK_FILESYSTEM, d2 FAN_MARK_MOUNT)
images/floor/                 the privileged c13 floor probe (loop device + raw read below the VFS)
evidence/                     receipted observed-matrix / arm-a-d0 / negative-control / floor-c13 json
results/                      numbered, append-only lab notebook (00 substrate .. 04 ladder+controls)
arm-b/                        drop Harbor trial dirs here; arm_b.py scans them (gated on the data)
transform/                    base Terminal-Bench 2.1 -> HV form (Apache-2.0 clean)            [next]
```

## What it does not do

It does not block reads on this substrate (the kernel lacks the fanotify permission config; that is
a one-line change on a kernel that has it). It does not claim separate-machine isolation - subject
and monitor share the LinuxKit VM kernel. It does not close the content-duplication or sub-VFS
channels, and says so in the same table that reports the ones it does close.
