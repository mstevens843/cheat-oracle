# 10 - Arm B redownload, scored-trial denominator, and final gate

Working record. This entry follows `results/09`: Docker evidence had been regenerated, and Harbor
access was available, so Arm B was redownloaded and rescanned instead of leaving the trace evidence
as an older lower-bound receipt.

## Harbor verification

Commands run:

```
scripts/fetch-hvtb-traces.sh --verify
scripts/fetch-hvtb-traces.sh /private/tmp/cheat-oracle-hvtb-jobs
uv run python -m cheat_oracle.harness.arm_b \
  --traces /private/tmp/cheat-oracle-hvtb-jobs \
  --key-path admin/ \
  --score-field hidden_solution \
  --out evidence/arm-b.json
```

Result:

- All 25 pinned Harbor job IDs resolved to the expected job name and 89 planned trials.
- Harbor's own eval rows summed to 2,224 scored trials, 224 `hidden_solution = 1`, 2,000 scored
  clean, and 1,801 task-reward successes.
- The downloaded corpus contains 25 job directories and 2,225 trial directories.
- The scanner now records the one-trial gap explicitly instead of folding it into the clean
  denominator: 2,225 directories, 2,224 HVTB-scored trials, 2,000 clean-scored trials, 1 unscored
  directory, 38 with no parsed commands, and 0 undercounts.
- The unscored directory is `hvtb-gemini-3.1-pro-ablation/mailman__Cd6r9Zp`.
- New receipt: `co1_88ee2ab347334209a0defd666e645f55c0c83f45804ccf9f6662384308a7fe40`.

This corrects the release-facing denominator from "0 of 2,001 clean-scored" to "0 of 2,000
clean-scored among 2,224 HVTB-scored trials in a 2,225-directory corpus." The null lower-bound result
is unchanged.

## Guard changes

`src/cheat_oracle/harness/arm_b.py` now distinguishes a missing score from a clean score with an
explicit `hvtb_score_present` field. `tests/test_arm_b_evidence.py` re-derives the 2,224 scored / 1
unscored split from the per-trial rows and pins the unscored trial outside the clean denominator.

Expected suite size after this entry: 147 tests.

## Remaining limits

- Arm B remains a command-level lower-bound scan, not a rerun of the agents.
- Redownloading traces still depends on Harbor continuing to expose the pinned job IDs.
- The traces are not redistributed in this repository.
