# 07 - Guarding the headline numbers, and what auditing our own prose found

> **2026-09-01 supersession:** this entry's Arm B guard discussion used the earlier
> `evidence/arm-b.json` schema and denominator. The current guarded artifact records 2,225 trial
> directories, 2,224 HVTB-scored trials, 2,000 clean-scored trials, 1 unscored directory, 0
> undercounts, and receipt `co1_88ee2ab347334209a0defd666e645f55c0c83f45804ccf9f6662384308a7fe40`.
> See `results/10-arm-b-rerun-correction.md`. The body below is preserved as the original
> `results/07` audit record.

Working record. No new measurement here and no new claim: this entry closes the gap between what the
repo asserts about itself and what it enforces. The project's rule is "do not cite a number that
does not name the command that produced it". Applied to the repo itself, three things failed it.

## Finding 1 - the two loudest numbers were the two nothing checked

`tests/test_discrimination.py` and `tests/test_negative_controls.py` each re-derive their artifact's
receipt so "a hand-edited number is caught". That guard covered `observed-matrix.json` and
`negative-control.json`. It did not cover:

- `evidence/arm-a-d0.json` - the **7 of 12** Arm A undercount, the first number in README.md;
- `evidence/arm-b.json` - the **0 of 2,001** Arm B null result;
- `evidence/floor-c13.json` - the measured c13 floor.

So the two most-cited numbers in the repo were editable with a text editor and a green suite. Three
guards added, in the same shape as the two that existed: re-derive the receipt, then assert the
public claim rather than only its hash.

- `tests/test_arm_a.py` - the count is 7 of 12 exercised; the seven are the named seven; the three
  outcome sets partition all 13 modelled channels; **every counted channel has `obtained: true`**, so
  the claim is "the key was obtained AND the detector stayed quiet", not just the second half; the
  undercount is a subset of the model's d0 miss set; the only disagreement is the c08 substrate cell.
- `tests/test_arm_b_evidence.py` - 2,225 scanned, 2,001 clean, 38 with no parsed commands, 0
  undercounts, **each re-counted from the 2,225-row `scans` array** so a summary edited without its
  rows disagrees with itself; the scan parameters (`admin/`, `hidden_solution`, `clean_reward` 0.0);
  the corpus is 25 jobs of 89; and the positive control - the single evasion-shaped command in the
  whole corpus - is present, is c02, and sits in a trial HVTB DETECTED. Without that last assertion a
  zero is indistinguishable from a scanner that matches nothing.
- `tests/test_floor.py` - obtained via the raw device, the VFS positive control fired, the raw read
  stayed silent, `floor_holds` equals the conjunction of the three, and the probe was not gated.

### The guards are attacked, and the attack is a test

A guard that cannot fail is not a guard. This was first established by hand-editing `evidence/`
twelve times and watching pytest go red, which proved it once, on one machine, and left nothing
anyone else could run. A claim about rigour that cannot be re-run is exactly what this repo refuses
to accept from HVTB, so it is now `tests/test_guard_mutations.py` and runs in CI.

It attacks the threat model that actually matters. A receipt only catches a NAIVE edit: the
canonicalization lives in `src/cheat_oracle/canonical.py`, so anyone changing a number can recompute
a valid receipt in one line. So each mutation is **resealed** - corrupt one published number, then
give the record a correct receipt - which means the receipt check passes and only the claim
assertions can object. 20 mutations across all five artifacts, every one rejected; one forges
the receipt instead, to prove the receipt check itself is live. A control test requires the
unmutated artifacts to still pass, so the whole thing cannot green by rejecting everything.

**Writing it found a real hole.** "The only predicted-vs-observed disagreement is c08" was a SUBSET
check in both the ladder guard and the new Arm A guard, and an empty list is a subset. So deleting
the recorded disagreements passed - meaning a future run that disagreed with the model on a new
channel could be made to look clean by removing the row instead of explaining it, while RESULTS.md
went on saying "predicted == observed in every exercised cell except c08". Both guards now re-derive
the disagreement list from the observed cells and require an exact match. That hole predates this
patch; the audit is what surfaced it.

## Finding 2 - a latent precedence bug in the Arm B scanner

`_read_score` read `verifier/reward.txt` FIRST and only fell back to `reward.json[--score-field]`.
On a trial that ships both files - a layout `arm-b/README.md` documents as supported - an explicit
`--score-field hidden_solution` was silently discarded and the run scored by TASK SUCCESS instead. That
inverts `--clean-reward`: a successful trial (reward 1) would be classed not-clean and dropped from
the denominator, taking any evasion in it out of the count. A malformed `reward.txt` also returned
`None` instead of falling through.

Fixed: `reward.json[score_field]` takes precedence, `reward.txt` is the legacy fallback, and an
unparseable `reward.txt` no longer blocks the JSON path. Four tests added (both files present;
malformed txt with valid json; txt-only in both directions; neither file present). Reverting
`_read_score` to the old body fails two of them, so the regression is pinned rather than asserted.

**The published number is unaffected, and that is corroborated from outside this repo rather than
argued from its own output.** Reasoning "2,001 is the hidden_solution split, so hidden_solution must
have been read" would be circular - 2,001 is what the scanner itself produced. Harbor publishes
HVTB's own per-job flag rates, so the split can be recomputed without this repo's scanner at all
(`scripts/fetch-hvtb-traces.sh --verify`, 2026-08-28):

```
  trials in Harbor eval rows       : 2224
  hidden_solution = 1 (detected)   : 224
  => scored clean by HVTB          : 2000
  trials with task reward = 1      : 1801
```

224 detected is exactly the `2225 - 2001` the scanner implies. The second line is what settles it:
task reward is 1 on 1,801 of 2,224 trials, so a reward-scored read of this corpus would have called
about 423 trials clean, not 2,001. The old precedence therefore cannot have produced the published
count, whether or not a `reward.txt` sat beside the JSON. That is a deduction from Harbor's numbers,
not from the scanner's own output, which is the whole point - the obvious argument ("2,001 + 224 =
2,225, so hidden_solution must have been read") is circular, since any binary split of 2,225 has that
shape.

What remains unverified, stated plainly: nothing on disk records whether those job directories
carried a `reward.txt` at all, and the corpus was wiped, so that specific fact is not re-derivable
here. It no longer needs to be - the count rules out the reward-scored reading either way - but the
file layout itself is an assertion, not a measurement. Re-running the scan after
`scripts/fetch-hvtb-traces.sh` would settle it against the pinned receipt.

The one-trial gap (2,225 trial directories against 2,224 with a Harbor eval row) is real, and is why
`results/06` quotes 2,000 against Harbor's denominator while `evidence/arm-b.json` reports 2,001
against its own.

## Finding 3 - the repo's own prose had drifted

Every numeric claim across README.md, RESULTS.md, DISCLOSURE.md, `arm-b/README.md` and
`results/00-06` was re-checked against `evidence/*.json`, the model source, and live command output.
Fifteen were wrong. All fifteen are accounted for below: seven corrected in place, five covered by a
superseded banner, three left standing because they are as-of suite sizes, not errors.

| where | was | now |
|---|---|---|
| RESULTS.md gate table | `69 passed` | `128 passed` |
| RESULTS.md, negative-control bullet | "a detector that **catches** 7 of 12 hacks" | a measured 7-of-12 **undercount** |
| results/04, negative-control section | same inversion | same fix |
| results/06, trace census | "0 across **2,000** trials, 1 across 224" (= 2,224) | 2,001 + 224 = 2,225 |
| results/03, recovered channels | "`fired.key = 1` **each time**" | 2 for c10, 1 for c11 |
| results/02, caught set | "caught **only**" then four items | five, naming c08 and why it is excluded |
| results/02, disagreements | "the **two** places it did not [agree]" against "11 of 12" | one (c08), plus the pre-run c06 correction |

The 7-of-12 inversion is the one worth naming: it is the repo's most-quoted number, stated backwards
in two places. Seven of twelve is what the HVTB replica MISSED. It caught five.

Two entries were superseded rather than rewritten, following the `results/05` precedent:

- **results/01** is a pre-correction snapshot. Four of its numbers moved when the harness put c06 into
  d0's FIRES set (`results/02`), and its matrix block is captured output of `python -m
  cheat_oracle.model` from 2026-08-25 that no longer matches the live command. A dated banner names
  all four; the body stands. The model being wrong there is the point of keeping it.
- **results/00** gate 3 said the traces had "no documented download path". Superseded by `results/06`
  and now by the pinned IDs; the licensing decision it reached is unchanged.

The three left standing are the as-of suite sizes in results/01 (43), results/04 (66) and results/05
(69). results/06's 70 was current when the sweep ran and is stale only because this entry added
tests, so it stands for the same reason. Each was true when written and rewriting them would falsify
the notebook; RESULTS.md carries the current gate, and now says which document is which.

## Finding 4 - Arm B could not be re-run by anyone, including us

RESULTS.md listed a one-line command for Arm B whose input no longer existed: the traces lived in
`/private/tmp/cheat-oracle-hvtb-jobs` and a reboot wiped them, and the 25 Harbor job IDs were written
down nowhere. `harbor hub job list` cannot recover them - on an authenticated account it returns an
empty page for `--scope my`, `--scope shared` and `--scope all`, with and without `--search hvtb` -
and `harbor hub job download` takes a UUID only, with no name-based form.

The IDs were recovered verbatim from the executed-command log of the 2026-08-27 download session and
pinned in `scripts/fetch-hvtb-traces.sh`. Rather than assert they are good, the script can prove it:

```
scripts/fetch-hvtb-traces.sh --verify      # resolves all 25 against Harbor, downloads nothing
-> All 25 pinned IDs resolve to the expected job name and 89 trials.
```

25 of 25 resolved, every `name` matched the job directory recorded in `evidence/arm-b.json`, every
`n_planned_trials` was 89. The download path additionally checks 25 job dirs and 2,225 trial dirs
(counted as `<job>/<trial>/agent`, the shape the scanner needs, not a name convention) and refuses to
hand off a partial corpus.

This makes the SCAN reproducible and the DOWNLOAD honestly external: if the org unshares a job it is
not recoverable by name, and the script says so instead of degrading quietly. RESULTS.md now
separates the two.

## Housekeeping that was overdue

- `.github/workflows/ci.yml` - pytest, ruff, mypy on push and PR. It grades the committed receipted
  evidence; it does not re-measure, because the container arms need Docker, fanotify and a privileged
  loop device. The workflow file says so rather than implying a green badge means the containers ran.
- `LICENSE` (MIT) - `pyproject.toml` declared MIT and "license-clean" is load-bearing in `results/00`
  and DISCLOSURE.md, but the file was absent.
- `uv.lock` un-ignored and committed; CI uses `uv sync --locked` so a floating ruff or mypy release
  cannot turn the suite red for a reason unrelated to the code.
- `.gitkeep` in `transform/` and `arm-b/traces/`, both documented in README.md and neither present on
  a fresh clone. `arm-b/.gitignore` narrowed to `traces/*` + `!traces/.gitkeep` so real trace data
  still stays out.
- `tool.ruff.extend-exclude` now names `.venv` explicitly. ruff skips it only by way of `.gitignore`
  and only inside a git work tree, so `ruff check .` could go red on a vendored virtualenv. Found by
  running the CI steps against a tarball checkout rather than trusting that the local run was
  representative.

## Checks

`uv run pytest` **128 pass, up from 70**. The 58 new, by file:

```
tests/test_arm_a.py             9   Arm A guard (7-of-12, the named seven, obtained, re-derivation)
tests/test_arm_b_evidence.py    7   Arm B guard (2225/2001/38/0, corpus shape, positive control)
tests/test_floor.py             7   c13 floor guard (obtained / VFS-fires / raw-silent / not gated)
tests/test_guard_mutations.py  26   the audit: 5 artifact-presence, 20 resealed edits, 1 control
tests/test_arm_b.py            +4   score precedence (both files, malformed txt, txt-only, neither)
tests/test_discrimination.py   +3   exact published sets + re-derivation from the observed cells
tests/test_negative_controls.py +2  the control subject, and deriving the summary from the run
```

ruff clean; mypy --strict clean on 35 files; zero em-dashes; every file touched is pure ASCII. All
five `evidence/*.json` receipts re-derive, and `evidence/` is byte-unchanged by this entry - nothing
here re-measured anything.

The patch was itself reviewed adversarially before it landed, on six lenses (are the new guards
vacuous; is the precedence change correct; did the corrections miss or break a number; will CI be
green on a fresh runner; what did the patch fail to deliver; does it overclaim), with every finding
independently refuted before it counted. Eleven survived and are fixed above. The one that mattered
most was a **blocker**: `astral-sh/setup-uv` publishes no floating major tag - `refs/tags` carries
`v10.0.0` and `v10.0.1` only - so the `@v10` first written here would not have resolved and the CI
badge would have been red on its first run. Confirming that the latest RELEASE was v10.0.1 was not
the same as confirming the tag existed, which is the same class of mistake this entry is about.

Still gated, unchanged and stated: kernel-level blocking (`FAN_ACCESS_PERM`, absent on this kernel),
separate-machine isolation, the c08 overflow substrate case, and the base Terminal-Bench 2.1 ->
HV-form transform (`transform/`). No headline depends on any of them.
