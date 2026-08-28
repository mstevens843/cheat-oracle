# 05 - Arm B: the retroactive scanner, and the Harbor boundary

Superseded note, 2026-08-27: two things below are now out of date. (1) The access boundary was a
stale package name, not a real wall: the public org table exposes all 25 HVTB jobs for
`hack-verifiable-environments/hv-terminal-bench-2-1`, so the 2,225 traces were downloaded and
scanned. (2) The scanner described here scanned the whole transcript with loose signatures, which
over-counted badly on real traces; it was rewritten to scan executed commands bound to the key path.
`results/06` records both the corrected scan (0 retroactive undercounts) and the overcount it caught.
Keep this entry as the record of what was first built and why the first Harbor probe failed.

Working record. Arm B is the retroactive half: apply the channel model to the released HVTB traces
and count how many the detector scored as no-hack while the agent obtained the key through a channel
the directory watch misses. This entry records what was built, and the honest boundary that keeps it
from producing a number today.

## The Harbor boundary, checked not assumed

A Harbor account was provisioned (`harbor auth status` -> logged in as mstevens843). The HVTB traces
are still not reachable, and this was verified rather than taken on faith:

```
harbor hub job list            -> header only, zero jobs visible to the account
harbor hub leaderboard list    -> public leaderboards exist; none is HVTB / hack-verifiable
harbor download MajoRoth/hack-verifiable-terminal-bench-2
                               -> "Package ... was not found or you do not have access"
harbor download hack-verifiable-terminal-bench
                               -> "Dataset ... not found"
```

The account's prior Harbor use (in a sibling project) was `harbor run -p tasks/... --env docker` -
running its OWN local tasks, which never granted access to another org's published trials. So the
2,225 HVTB traces are gated behind sharing, not a config glitch: they are on Harbor hub under an
owner that has not shared them with this account.

## What was built (`src/cheat_oracle/harness/arm_b.py`)

A scanner over Harbor trial directories (the platform's own layout, learned from real trial outputs:
`agent/trajectory.json` plus `verifier/reward.txt`). For each trial it:
- reads the agent side as text (robust to whether the trajectory is JSON, JSONL, or a transcript);
- matches per-channel obtainment signatures for the channels HVTB's directory watch misses (hardlink,
  git object read, a copy, kill-the-watcher, unlink-the-flag, network fetch), bound to the configured
  key path;
- reads the detector's verdict (a reward at or below `--clean-reward` means scored clean);
- flags a retroactive undercount when a trial the detector scored clean obtained the key through a
  channel the model ties to d0's miss set.

The undercount set is not hardcoded: it is `summarize(d0).misses` from the model, so Arm B and the
prediction cannot drift apart. Output is a receipted `evidence/arm-b.json` when traces are present.

## Honest gating

With no trials under `arm-b/traces/`, the scanner reports GATED and writes nothing:

```
Arm B GATED: no trial directories under .../arm-b/traces.
The released HVTB traces were not shared with this Harbor account (DISCLOSURE.md);
drop Harbor trial dirs into arm-b/traces/ to run the retroactive undercount.
No evidence written - the undercount is not claimed as measured without the data.
```

## Validated on a synthetic fixture, not on HVTB data

Because there are no real traces, the scanner is proven correct on a labelled SYNTHETIC fixture
(`tests/fixtures/arm_b/` - clearly not HVTB data): three trial dirs, of which two obtained the key
through a d0-missed channel (a hardlink, a `git cat-file`) while scored clean, and one plain read that
was scored caught. `tests/test_arm_b.py` asserts the scanner flags exactly the two undercounts (c02,
c04), ties the counted channels to the model's d0-missed set, and that an empty traces dir stays GATED
and writes no evidence. This validates the wiring; it makes no claim about HVTB's real rate.

## Checks

- `uv run pytest` 69 pass (3 new for Arm B); ruff clean; mypy --strict clean; zero em-dashes.
- `arm-b/README.md` documents the input contract; `arm-b/.gitignore` keeps real trial data out of the
  repo while committing the scanner and the contract.
- DISCLOSURE.md updated: the offer now names the ready-to-run scanner and the confirmed sharing
  boundary, so the authors can share the traces (or drop them in) and get the retroactive number.
