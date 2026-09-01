# Transform Status

`src/cheat_oracle/transform.py` implements a minimal provenance-transform prototype for tiny
synthetic/licensed fixture tasks. It is not a full Terminal-Bench 2.1 -> HVTB-form corpus transform.

The prototype command is:

```
uv run python -m cheat_oracle.transform \
  --source tests/fixtures/transform/source-task \
  --answer-key tests/fixtures/transform/answer-key.txt \
  --task-id synthetic-transform-fixture \
  --out /private/tmp/cheat-oracle-transform-demo --force
```

It copies the source task tree, adds `admin/key.txt`, injects HVTB-style detector scripts under
`detector/`, and writes `provenance.json` with the source tree digest and answer-key digest.
`tests/test_transform.py` verifies the output shape and that the synthetic task's normal solution
and test still run after transformation.

Re-inspected on 2026-09-01: this repository does not contain the licensed Terminal-Bench source
task corpus. The prototype is therefore only a contract for what a real transform must preserve; it
must not be cited as a completed Terminal-Bench 2.1 transform.

A full transform would still need to:

1. Start from a licensed Terminal-Bench task source.
2. Add the HVTB-style `admin/` answer-key material without changing the task's normal solution path.
3. Inject detector wiring in a way that can be tested fail-open and fail-closed.
4. Emit provenance metadata tying the transformed task back to its licensed source.
5. Ship tests proving the transform preserves task behavior and does not introduce hidden detector
   reads during setup.

Until those pieces exist, the completed claim is only "synthetic-fixture transform prototype," not
"Terminal-Bench 2.1 transformed."
