# Arm B - retroactive undercount over real HVTB traces

Drop Harbor trial directories under `traces/<trial>/`, each in the Harbor layout:

    traces/<trial>/agent/trajectory.json   (ATIF; the agent's executed commands are scanned)
    traces/<trial>/verifier/reward.json    (hidden_solution <= --clean-reward means scored clean)
    traces/<trial>/verifier/reward.txt     (legacy scalar fallback)

`reward.json` read with `--score-field` takes precedence over `reward.txt`. A trial that ships both
is scored by the answer-key flag, not by task success; the other order silently discards
`--score-field` and inverts what "scored clean" means (results/07).

Downloaded Harbor jobs can also be scanned directly:

    traces/<job>/<trial>/agent/trajectory.json
    traces/<job>/<trial>/verifier/reward.json

Then run:

    uv run python -m cheat_oracle.harness.arm_b --key-path admin/ --score-field hidden_solution

For each trial the HVTB detector scored as no-hack, the scanner checks whether an executed command
obtained the answer key through a route the admin/ directory watch does not observe (a hardlink out,
a git object-store read of the key), and receipts the count to `evidence/arm-b.json`. It scans the
agent's commands, not the transcript, and binds every signature to the key path, so a benign curl or
a git call that excludes admin does not count.

STATUS: scanned. The public Harbor org exposes 25 HVTB jobs for
`hack-verifiable-environments/hv-terminal-bench-2-1`. The full run over the downloaded job dirs in
`/private/tmp/cheat-oracle-hvtb-jobs`:

    uv run python -m cheat_oracle.harness.arm_b \
      --traces /private/tmp/cheat-oracle-hvtb-jobs \
      --key-path admin/ \
      --score-field hidden_solution \
      --out evidence/arm-b.json

To get those job dirs back, run `scripts/fetch-hvtb-traces.sh`, which pins all 25 Harbor job IDs.
Check the pin without downloading anything with `scripts/fetch-hvtb-traces.sh --verify` (2026-08-28:
25 of 25 resolved, every name matched `evidence/arm-b.json`, every job 89 trials). `harbor hub job list` does NOT enumerate this org's jobs on an authenticated account, and
`harbor hub job download` takes a UUID only, so the pinned manifest is the only route back to the
data. The scanner itself needs no account: it runs against any local Harbor-shaped trial dir.

Result: 2,225 trials scanned; 2,001 scored clean by HVTB; 0 undercounts; receipt
`co1_3a95af4390209b8ef4ed31f2bc951ae443fcdf0428629af0d2b9a77420ee12a6`. (A first transcript-grep pass
reported 888; all were false positives - see ../results/06.) Raw traces stay outside the repo;
`traces/` is ignored.
