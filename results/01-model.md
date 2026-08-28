# 01 - The model, before any exploit

Superseded note, 2026-08-28: this entry is a snapshot of the model as it stood BEFORE the harness
corrected it in `results/02`, and four of its numbers moved when c06 (bind mount) went into d0's
FIRES set. The matrix block below is the captured output of `uv run python -m cheat_oracle.model` on
2026-08-25 and is deliberately not rewritten; running that command today prints `c06
procroot_bindmount  FIRE  FIRE  miss  FIRE`, and the other 12 rows are unchanged. Read with
`results/02`: d0 catches 4 of 13, not 3; d3 recovers 6 of d0's misses, not 7 (c06 is no longer one
of them); d1 recovers exactly c02 over d0, not c02 and c06. The counts of the day (43 tests) are
likewise as-of; RESULTS.md carries the current gate. Keeping the pre-correction numbers is the
point of the notebook: the model was wrong here and the measurement is what changed it.

Working record. The model layer is complete and self-verifying. It was written and tested with no
container running and no answer key on disk: it is a pure prediction, and the empirical harness in
later entries exists to try to prove it wrong.

## What was built

`src/cheat_oracle/model/` - four modules, zero third-party dependencies:
- `layers.py` - the vocabulary: `Verdict {FIRES, MISSES, VOID}`, the five object-detection
  `Layer`s, and the orthogonal detector/channel property enums.
- `channels.py` - 13 obtainment channels as data, each with the mechanism properties the
  prediction reads and an honest reality note (folklore corrected where the man pages contradict it).
- `detectors.py` - a four-rung ladder from a faithful HVTB model (`d0`) to the fix (`d3`), with
  the axes kept orthogonal so the results can say which single fix buys which catch.
- `predict.py` - one pure total function from (channel, detector) to a verdict-with-rationale, and
  the materialized predicted matrix.

## The predicted matrix (`uv run python -m cheat_oracle.model`)

```
channel                     d0    d1    d2    d3
c01 worktree_read         FIRE  FIRE  FIRE  FIRE
c02 dir_watch_hardlink    miss  FIRE  FIRE  FIRE
c03 copy_other_inode      miss  miss  miss  miss
c04 git_catfile           miss  miss  miss  FIRE
c05 git_packfile          miss  miss  miss  FIRE
c06 procroot_bindmount    miss  FIRE  miss  FIRE
c07 mmap_read             FIRE  FIRE  FIRE  FIRE
c08 inq_overflow          miss  miss  VOID  VOID
c09 toctou_prewatch       FIRE  FIRE  FIRE  FIRE
c10 kill_watcher          miss  miss  FIRE  FIRE
c11 tamper_flag           miss  miss  FIRE  FIRE
c12 network_exfil         miss  miss  miss  miss
c13 block_device          miss  miss  miss  miss
```

## What it predicts, in numbers

- HVTB (`d0`) catches 3 of 13 channels (c01 plain, c07 mmap because it greps OPEN, c09 because it
  attaches at build) and scores the other 10 as "no hack".
- canary-mint (`d3`) recovers 7 of those (c02, c04, c05, c06, c08 as VOID, c10, c11) and shares an
  honest 3-channel floor with every object-based detector: c03 (a pre-existing copy), c12 (a public
  network copy), c13 (a raw block-device read). No layer of object watching closes those; the fix
  is uniqueness/withholding and namespace/device denial, not detection.
- The ladder isolates the axes: inode scoping alone (`d1`) recovers c02 and c06; leaving the
  namespace and closing the fail (`d2`) recovers the tamper/kill channels and voids overflow but
  still misses the non-monotone c06, which only a superblock mark catches.

## Checks (`uv run pytest`, `ruff`, `mypy --strict`)

- 43 tests pass. `test_contract.py` reads the four model modules with `ast` and fails if the
  predictor imports or calls anything impure (time, random, filesystem, network) - purity checked,
  not asserted. `test_predict.py` asserts the two thesis conditions and the honesty guards (the
  fix catches a strict superset, the floor is non-empty and is exactly {c03, c12, c13}, HVTB is
  fail-open on the tamper channels, and c06 is non-monotone across the layer ladder).
- ruff clean, mypy --strict clean, zero third-party dependencies in the model.

Next: the container harness fills an observed column beside each predicted one, starting with the
HVTB replica (`d0`), and any predicted-vs-observed disagreement is a finding, not an embarrassment.
