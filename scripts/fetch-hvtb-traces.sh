#!/usr/bin/env bash
# Fetch the 25 released HVTB jobs that Arm B scanned, so evidence/arm-b.json can be re-derived
# rather than taken on trust.
#
# WHY THIS FILE EXISTS. The traces are not in the repo (they are ~2 GB and not ours to
# redistribute), and the run recorded in results/06 wrote them to /private/tmp, which a reboot
# wiped. Without the job IDs below, the single command RESULTS.md gives for Arm B could not be run
# by anyone, including the author. The IDs are the reproducibility.
#
# WHERE THE IDS COME FROM, AND WHAT IS STILL AN EXTERNAL DEPENDENCY.
#   - Recovered verbatim from the executed-command log of the 2026-08-27 download session, then
#     each one re-checked live on 2026-08-28 and again on 2026-09-01 with `harbor hub job download`'s sibling
#     `harbor hub job show <id> --json`: 25 of 25 resolved, every `name` matched the job directory
#     name recorded in evidence/arm-b.json, every `n_planned_trials` was 89.
#   - `harbor hub job list` CANNOT find these jobs. On an authenticated account it returns an empty
#     page for `--scope my`, `--scope shared`, and `--scope all`, with or without `--search hvtb`.
#     There is no name-based download form: `harbor hub job download` requires a UUID. So this
#     manifest is not a convenience, it is the only documented route back to the data.
#   - Therefore Arm B's DOWNLOAD step is externally dependent: it needs a Harbor account to which
#     the `hack-verifiable-environments` org still exposes these jobs. If a download 404s, the job
#     was unshared or moved, and no fallback exists here. The SCAN step has no such dependency: it
#     runs against any local Harbor-shaped trial directory (see arm-b/README.md).
#
# Usage:  scripts/fetch-hvtb-traces.sh [OUT_DIR]     (default /private/tmp/cheat-oracle-hvtb-jobs)
#         scripts/fetch-hvtb-traces.sh --manifest    (print the 25 id/name pairs and exit)
#         scripts/fetch-hvtb-traces.sh --verify      (resolve each ID against Harbor, download nothing)
#
# `--verify` is what makes the paragraph above checkable rather than a claim: it asks Harbor for each
# of the 25 IDs and reports whether the returned name and planned-trial count match this manifest.
# It then sums HVTB's OWN published per-job flag rates to recompute the detected/clean split without
# this repo's scanner, which is the independent check on evidence/arm-b.json's denominator.
# Anyone with an account that can see the jobs can run it and get the same numbers.

set -euo pipefail

EXPECTED_JOBS=25
EXPECTED_TRIALS_PER_JOB=89
EXPECTED_TRIALS=2225
EXPECTED_SCORED_TRIALS=2224
EXPECTED_DETECTED=224
EXPECTED_CLEAN=2000
EXPECTED_UNSCORED=1
DATASET="hack-verifiable-environments/hv-terminal-bench-2-1"

# <job-id> <job-name>. Names are the directory names that appear in evidence/arm-b.json's per-trial
# labels; the test suite re-counts 25 jobs of 89 from that artifact, so this list and the published
# scan cannot drift apart silently.
read -r -d '' JOBS <<'MANIFEST' || true
70f69025-3d04-4289-aa62-9eba0eb24c08 hvtb-claude-opus-5-L0
31690d34-bc55-4e10-9a2e-f0ea3dcfaa52 hvtb-claude-opus-5-L1
267e792b-1ecf-4ac6-a0c6-ab0ff72352db hvtb-claude-opus-5-L2
564c4628-9264-4575-90a4-043e89473d78 hvtb-claude-opus-5-L3
19161777-df3f-4232-9906-0f77520e1e98 hvtb-claude-opus-5-ablation
6d831c9e-d45a-4a6d-b4b1-38242338103b hvtb-gemini-3.1-pro-L0
8d54ad79-c435-4c8f-accd-6ef178e2cd9c hvtb-gemini-3.1-pro-L1
9afa629c-8d5b-4230-8b1f-b6c550fa2742 hvtb-gemini-3.1-pro-L2
b989030e-0e79-4593-be8f-a773d3c58f76 hvtb-gemini-3.1-pro-L3
5ed558d7-ee40-456f-9697-a791b61648e7 hvtb-gemini-3.1-pro-ablation
2b1ce716-6154-4b44-a68f-32e209f13dcd hvtb-glm-5.2-L0
ec056ef2-40f7-4b72-8329-07d6941f3777 hvtb-glm-5.2-L1
a9e8711c-8585-452f-a552-539fa5c938b9 hvtb-glm-5.2-L2
c6be9f38-127d-450b-8c75-e3e6778c5384 hvtb-glm-5.2-L3
41999802-e81d-475e-82c3-531c27d7cc87 hvtb-glm-5.2-ablation
59ff1d1e-5f6f-431d-92e2-7e4a7429a130 hvtb-gpt-5.6-sol-L0
8e3ab605-9cc8-40d9-a37f-36cd19d18904 hvtb-gpt-5.6-sol-L1
688853ba-5104-4acf-b4c2-a6efab9eae7b hvtb-gpt-5.6-sol-L2
67263c53-e84c-4a03-a4e6-c9ef737288a4 hvtb-gpt-5.6-sol-L3
5a83bf48-30f2-495a-8725-83e85a4d2bf7 hvtb-gpt-5.6-sol-ablation
45617deb-c410-4aeb-9e0b-ec0628525a0e hvtb-kimi-k3-L0
94d4b319-f979-4540-b30e-3057ab4f2df8 hvtb-kimi-k3-L1
dd71ad9f-314c-4806-8665-d97cc944bcf7 hvtb-kimi-k3-L2
db407c5f-68ad-468c-922a-b342ad03289c hvtb-kimi-k3-L3
52d27bfa-7d52-4654-b3f9-f87dc091dff4 hvtb-kimi-k3-ablation
MANIFEST

validate_manifest() {
  count=$(printf '%s\n' "$JOBS" | awk 'NF {print $1}' | wc -l | tr -d ' ')
  if [ "$count" != "$EXPECTED_JOBS" ]; then
    echo "FAIL: manifest has $count jobs, expected $EXPECTED_JOBS." >&2
    exit 1
  fi

  dup_ids=$(printf '%s\n' "$JOBS" | awk 'NF {print $1}' | sort | uniq -d | tr '\n' ' ')
  if [ -n "$dup_ids" ]; then
    echo "FAIL: duplicate Harbor job IDs in manifest: $dup_ids" >&2
    exit 1
  fi

  dup_names=$(printf '%s\n' "$JOBS" | awk 'NF {print $2}' | sort | uniq -d | tr '\n' ' ')
  if [ -n "$dup_names" ]; then
    echo "FAIL: duplicate Harbor job names in manifest: $dup_names" >&2
    exit 1
  fi
}

validate_manifest

if [ "${1:-}" = "--manifest" ]; then
  printf '%s\n' "$JOBS"
  exit 0
fi

OUT="${1:-/private/tmp/cheat-oracle-hvtb-jobs}"

command -v harbor >/dev/null 2>&1 || {
  echo "FAIL: no 'harbor' on PATH. Install it (uv tool install harbor), then re-run." >&2
  exit 1
}
harbor auth status >/dev/null 2>&1 || {
  echo "FAIL: harbor is not authenticated. Run 'harbor auth login', then re-run." >&2
  exit 1
}

if [ "${1:-}" = "--verify" ]; then
  echo "Resolving $EXPECTED_JOBS pinned job IDs against Harbor (no download)."
  echo
  bad=0
  sum_trials=0
  sum_hidden=0
  sum_reward=0
  while read -r id name; do
    [ -n "$id" ] || continue
    got=$(harbor hub job show "$id" --json 2>/dev/null \
          | python3 -c 'import json,sys
try:
    d = json.load(sys.stdin)
except Exception:
    print("UNRESOLVED 0 0 0 0"); raise SystemExit
jobs = d.get("jobs") if isinstance(d, dict) else None
j = jobs[0] if isinstance(jobs, list) and jobs else (d if isinstance(d, dict) else {})
# Harbor also publishes per-row rates for HVTB own flags. Summing rate*n_trials over the eval
# rows gives a detected-access count computed by HVTB, entirely independent of this repo.
n = hs = rw = 0.0
for row in (d.get("evals", {}) or {}).get("rows", []) or []:
    k = row.get("n_trials") or 0
    m = {a: b for one in row.get("metrics", []) or [] for a, b in one.items()}
    n += k
    hs += (m.get("hidden_solution") or 0.0) * k
    rw += (m.get("reward") or 0.0) * k
print(j.get("name") or j.get("job_name") or "UNRESOLVED",
      j.get("n_planned_trials") or 0, int(n), round(hs), round(rw))' 2>/dev/null)
    set -- $got
    got_name="${1:-UNRESOLVED}"; got_n="${2:-0}"
    sum_trials=$((sum_trials + ${3:-0}))
    sum_hidden=$((sum_hidden + ${4:-0}))
    sum_reward=$((sum_reward + ${5:-0}))
    if [ "$got_name" = "$name" ] && [ "$got_n" = "$EXPECTED_TRIALS_PER_JOB" ]; then
      echo "  ok       $name ($id) $got_n trials"
    else
      echo "  MISMATCH $name ($id) -> got '$got_name' $got_n trials"
      bad=$((bad + 1))
    fi
    set --
  done <<< "$JOBS"

  echo
  if [ "$bad" -ne 0 ]; then
    echo "$bad of $EXPECTED_JOBS pinned IDs did not resolve to the expected name and trial count."
    echo "Either the org changed what it shares, or this manifest is stale. Do not treat"
    echo "evidence/arm-b.json as reproducible until this is resolved."
    exit 1
  fi
  echo "All $EXPECTED_JOBS pinned IDs resolve to the expected job name and $EXPECTED_TRIALS_PER_JOB trials."
  if [ "$sum_trials" != "$EXPECTED_SCORED_TRIALS" ] || [ "$sum_hidden" != "$EXPECTED_DETECTED" ]; then
    echo
    echo "MISMATCH: Harbor metrics changed from the recorded Arm B split."
    echo "  scored trials: got $sum_trials expected $EXPECTED_SCORED_TRIALS"
    echo "  detected:      got $sum_hidden expected $EXPECTED_DETECTED"
    exit 1
  fi
  echo
  echo "Independent corroboration of the Arm B split, from HVTB's own published per-job metrics"
  echo "(summed rate x n_trials over the eval rows; this repo's scanner is not involved):"
  echo "  trials in Harbor eval rows       : $sum_trials"
  echo "  hidden_solution = 1 (detected)   : $sum_hidden"
  echo "  => scored clean by HVTB          : $((sum_trials - sum_hidden))"
  echo "  trials with task reward = 1      : $sum_reward"
  echo
  echo "evidence/arm-b.json reports $EXPECTED_TRIALS trial dirs, $EXPECTED_SCORED_TRIALS scored,"
  echo "$EXPECTED_CLEAN scored clean, and $EXPECTED_UNSCORED unscored, so it implies"
  echo "$((EXPECTED_SCORED_TRIALS - EXPECTED_CLEAN)) detected among scored trials - compare above."
  echo "Note the scanner reads one more trial DIRECTORY than Harbor has an eval row for."
  echo "Scoring the same corpus by task reward instead would call about"
  echo "$((sum_trials - sum_reward)) trials clean, not $EXPECTED_CLEAN, which is why the published"
  echo "count could only have come from the hidden_solution field."
  exit 0
fi

mkdir -p "$OUT"
echo "Fetching $EXPECTED_JOBS HVTB jobs from $DATASET into $OUT"
echo

failed=""
while read -r id name; do
  [ -n "$id" ] || continue
  if [ -d "$OUT/$name" ]; then
    echo "  skip     $name (already present)"
    continue
  fi
  if harbor hub job download "$id" -o "$OUT" >/dev/null 2>&1; then
    echo "  ok       $name"
  else
    echo "  FAILED   $name ($id)"
    failed="$failed $name"
  fi
done <<< "$JOBS"

echo
# Count the scanner's actual predicate - a <job>/<trial> holding BOTH agent/ and verifier/, which is
# what _is_trial_dir requires - rather than the trial-name convention or agent/ alone, so a corpus
# that downloaded trajectories without verdicts cannot pass this gate.
n_jobs=$(find "$OUT" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')
n_trials=$(find "$OUT" -mindepth 2 -maxdepth 2 -type d \
             -exec test -d '{}/agent' -a -d '{}/verifier' ';' -print | wc -l | tr -d ' ')
echo "Downloaded job dirs: $n_jobs (expected $EXPECTED_JOBS)"
echo "Trial dirs:          $n_trials (expected $EXPECTED_TRIALS = $EXPECTED_JOBS x $EXPECTED_TRIALS_PER_JOB)"

if [ -n "$failed" ]; then
  echo
  echo "INCOMPLETE. These jobs did not download:$failed"
  echo "There is no fallback. 'harbor hub job list' does not enumerate this org's jobs on an"
  echo "authenticated account (empty page for --scope my|shared|all), and 'harbor hub job download'"
  echo "takes a UUID only, so a job the org has unshared cannot be recovered by name. Do not"
  echo "re-run the Arm B scan against a partial corpus and report the count as the published one."
  exit 1
fi

if [ "$n_jobs" != "$EXPECTED_JOBS" ] || [ "$n_trials" != "$EXPECTED_TRIALS" ]; then
  echo
  echo "INCOMPLETE: the corpus does not match the shape results/06 recorded. Do not report a"
  echo "count from a corpus of a different size without saying so."
  exit 1
fi

cat <<EOF

Complete. Re-derive the Arm B result with:

  uv run python -m cheat_oracle.harness.arm_b \\
    --traces $OUT --key-path admin/ --score-field hidden_solution \\
    --out evidence/arm-b.json

Expected: 2225 trials, 2224 scored, 2000 clean, 1 unscored, 38 with no parsed commands,
0 undercounts, receipt co1_88ee2ab347334209a0defd666e645f55c0c83f45804ccf9f6662384308a7fe40

Note: the receipt covers traces_dir, so re-running into a DIFFERENT output directory changes it.
Use the path above to reproduce the published receipt exactly.
EOF
