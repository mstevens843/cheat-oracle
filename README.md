# cheat-oracle

[![CI](https://github.com/mstevens843/cheat-oracle/actions/workflows/ci.yml/badge.svg)](https://github.com/mstevens843/cheat-oracle/actions/workflows/ci.yml)

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
license-clean reproduction and prepared for upstream disclosure. The offensive programs are detector
test cases. No exploit is pointed at a system the author does not control.

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
>   ledger is out of the subject's reach, and the monitor's own final-verdict certifier verifies the
>   hash chain and emits VOID if a required ledger is missing, malformed, truncated, or edited. The
>   same certifier is covered by `tests/test_ledger_certify.py` and the reflexive helper test.
> - **Arm B, the released traces, scanned - a null result, honestly.** The public Harbor org exposes
>   25 HVTB jobs over `hack-verifiable-environments/hv-terminal-bench-2-1`; the current corpus has
>   **2,225 released trial directories**, of which Harbor publishes HVTB score rows for **2,224**.
>   Scanning that corpus (`uv run python -m cheat_oracle.harness.arm_b --traces
>   /private/tmp/cheat-oracle-hvtb-jobs --key-path admin/ --score-field hidden_solution`) finds that
>   of the **2,000 scored clean by HVTB, 0** show a command that obtained the key through a
>   watch-evading route - the evasions Arm A proves possible were not observed being used in this
>   sample. A first pass reported 888 by grepping whole transcripts; reading the matches showed they
>   were false positives (a `curl`, base64 noise, `git` calls that EXCLUDED admin), so the scanner was
>   corrected to scan executed commands bound to the key path (`results/06`), then re-run with an
>   explicit unscored-trial count (`results/10`). Receipt:
>   `co1_88ee2ab347334209a0defd666e645f55c0c83f45804ccf9f6662384308a7fe40`.
> - **Every headline number is guarded, and the guards are themselves attacked, in the suite.** All
>   five receipted artifacts in `evidence/` have a test that re-derives the receipt and then asserts
>   the claim the paragraphs above make from it. Because a receipt only stops a naive edit - the
>   canonicalization is in this repo - `tests/test_guard_mutations.py` corrupts one published number
>   at a time, RESEALS the record with a valid receipt, and requires the claim assertions to reject it
>   anyway: drop a channel from the Arm A undercount, invent Arm B undercounts, delete the Arm B
>   positive control, truncate the corpus, erase the disagreements, silence the c13 positive control.
>   20 edits, all rejected: `uv run pytest`.
> - **The measurement corrected the model, twice.** It caught the model mispredicting the bind-mount
>   channel (`results/02`), then showed d2's out-of-container mount mark is blind cross-container - a
>   `FAN_MARK_MOUNT` is per-vfsmount, the measured reason the fix marks the superblock (`results/04`).
>   The core harness observed runs carry canonical-JSON SHA-256 receipts that their tests re-derive;
>   Arm B carries the scanner receipt above.
>
> **What remains infrastructure-gated or out of scope:** blocking rather than observing needs a
> kernel with `CONFIG_FANOTIFY_ACCESS_PERMISSIONS`; no separate-machine isolation has been
> implemented; c08 overflow remains substrate-dependent; no optional external PR against the HVTB
> prototype has been opened; and the optional base Terminal-Bench 2.1 -> HV-form provenance
> transform is not implemented (`transform/README.md`). None of the headline depends on the
> transform or external PR.
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
evidence/                     receipted observed-matrix / arm-a-d0 / negative-control / floor-c13 / arm-b json
results/                      numbered, append-only lab notebook (00 substrate .. 10 Arm B rerun)
arm-b/                        Harbor trial/job-dir scanner; raw traces stay out of the repo
scripts/fetch-hvtb-traces.sh  the 25 pinned Harbor job IDs Arm B scanned (re-verified 2026-09-01)
UPSTREAM.md                   inspected upstream boundary and PR patch scope; no PR opened here
transform/                    no transform yet; optional provenance work is explicitly out of scope
```

## What it does not do

It does not block reads on this substrate. The LinuxKit kernel lacks the fanotify permission config,
and a real blocker would need `FAN_ACCESS_PERM` plus allow/deny responses on a kernel that supports
permission events. It has not opened an optional external upstream PR against the HVTB prototype. It
does not claim separate-machine isolation - subject and monitor share the LinuxKit VM kernel. It
does not close the content-duplication or sub-VFS channels, and says so in the same table that
reports the ones it does close. The Dockerfiles are digest-pinned to manifest-list digests resolved
from Docker Hub on 2026-09-01; images were rebuilt on Docker Desktop's LinuxKit aarch64 substrate and
the receipted Docker evidence was remeasured in this pass.
