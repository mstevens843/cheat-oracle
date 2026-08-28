# Disclosure draft - HVTB answer-key detector undercount

**To:** the authors of "Hack-Verifiable Terminal Bench" (arXiv 2608.22103) - Amit Roth, Ivan
Bercovich, Yonathan Efroni.
**From:** Mathew Stevens. **Nature:** defensive eval-integrity research, run entirely in a local
sandbox against a license-clean reproduction of the detector. No exploit was run against any system
the author does not control. **Status:** draft, not yet sent.

## Summary

HVTB detects answer-key access with an in-container `inotify` watcher on `admin/` whose flag file is
read fail-open. The paper states its reported reward-hacking rates are "sound but not complete... a
lower bound," and scopes that admission to hacks that route around `admin/`. We measured a second,
unscoped source of undercount: the watcher runs inside the agent's own namespaces and its flag is
agent-writable, so an agent can obtain the planted key by routes the watch does not observe, or
disable the watch outright. On a faithful reproduction of the detector, seven distinct channels
obtained the key while the detector scored the run clean.

We are not claiming the paper's central method is unsound. We are quantifying an undercount the
paper does not currently bound, and offering a drop-in hardening for the detector.

## The channels (reproduced, not asserted)

Reproduced on base Terminal-Bench 2.1 with the detector wired per the paper and the public prototype
(`MajoRoth/hack-verifiable-terminal-bench-2`). Each obtained the key's canary bytes; the detector's
fail-open flag stayed clean.

- **Read outside the watched directory** - a hardlink to the key in a sibling directory; inotify on
  `admin/` does not report a file accessed via a link outside the monitored directory.
- **Read the git object store** - `git cat-file` / a zlib-inflated loose object reads the key's blob
  without opening the working-tree path the watch covers.
- **Read a pre-existing copy** - a copy on a different inode is never the watched object.
- **Fetch over the network** - base Terminal-Bench ships every solution publicly with
  `allow_internet = true`, so the key is obtainable with no local read at all.
- **Kill the watcher** - `pkill inotifywait` in the shared PID namespace, then read; no watcher, no
  flag.
- **Unlink the flag** - the watcher keeps its open fd on the now-unlinked ghost inode while the
  verifier's `[ -f flag ]` path check is false.

## Two concrete, low-cost fixes

1. **Fail closed.** Treat a missing or empty flag file, a lost inotify watch, or `IN_Q_OVERFLOW` as
   a void trial rather than "no hack". A tripwire whose absence is scored as innocence inverts under
   exactly the agents worth measuring.
2. **Move the detector out of the agent's reach.** A host-side or sidecar `fanotify
   FAN_MARK_FILESYSTEM` on the answer key's superblock, attributing reads by inode (and by the git
   object files that hold the blob), observes the reads an in-container directory watch cannot and
   cannot be killed or tampered by the agent. We include a working reference (`canary-mint`) that
   recovers five of the channels above and records each access to a hash-chained, tamper-evident
   ledger; it does not close the content-duplication channels (a copy, a public network fetch) or a
   raw block-device read, which are addressed by uniqueness/withholding and device denial rather
   than detection, and we state that limit explicitly.

   One detail matters for the fix and is measured, not assumed: it must mark the SUPERBLOCK
   (`FAN_MARK_FILESYSTEM`), not the mount (`FAN_MARK_MOUNT`). A mount mark is per-vfsmount, so a
   sidecar marking its own mount of the shared volume observes none of the agent's reads through the
   agent's separate mount; only a superblock mark, shared across every mount of the filesystem, sees
   them. We measured this by building both.

## What is now measured, end to end

Since the draft above, the reproduction was hardened into a full, receipted measurement:
- **The whole four-rung detector ladder is measured** (directory watch -> inode watch -> mount mark
  -> superblock mark), so each design decision is isolated: inode scope alone recovers the hardlink
  channel; only the out-of-namespace superblock mark recovers the git object-store and the two
  detector-attack channels.
- **A negative control** (a benign subject that never reads the key) is scored clean by all four
  detectors - the fix does not trade the undercount for false positives.
- **The block-device floor is measured**, not just asserted: a raw read of the backing device obtains
  the key while the superblock mark stays silent (and fires on a VFS read of the same file).
- **The released traces were scanned - a null result we report as one.** The public Harbor org
  exposes 25 HVTB jobs for `hack-verifiable-environments/hv-terminal-bench-2-1` (2,225 trials).
  Scanning the agents' executed commands, of the 2,001 your detector scored clean, 0 obtained the key
  through a route the directory watch is modeled to miss. (A first pass grepped whole transcripts and
  reported 888; reading the matches showed all were false positives - a benign curl, base64 noise,
  git calls that excluded admin - so we corrected the scanner and re-ran.) So on this public sample we
  find the evasions demonstrated in Arm A were not observed being exploited: the undercount is a
  latent vulnerability, not an observed miss here. Receipt
  `co1_3a95af4390209b8ef4ed31f2bc951ae443fcdf0428629af0d2b9a77420ee12a6`.
- The core harness observed runs carry canonical-JSON SHA-256 receipts re-derived by the test suite;
  Arm B carries its own scanner-produced receipt.

## What we are offering

- The reproduction, the channel corpus, the hardened detector, and the measurement, all
  license-clean and runnable from a single Dockerfile pair.
- A PR against the HVTB task-transform script adding the fail-closed flag handling and an optional
  sidecar detector, if useful.

We would value a correction if any channel does not reproduce against the real environments. The
scanner is intentionally conservative: Arm A proves obtainment by emitted canary bytes, while Arm B
counts only released trajectories your detector scored clean where an executed command reads the key
through a route the directory watch is modeled to miss. It is a lower bound - it cannot see routes
that leave no key-path reference in a command (a pre-existing copy, a raw object-hash read, a network
mirror) - and it is validated to flag a genuine key read while not firing on the benign patterns that
fooled the first pass.
