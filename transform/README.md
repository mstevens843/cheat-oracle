# Transform Status

No Terminal-Bench 2.1 -> HVTB-form provenance transform is implemented in this repository.

Re-inspected on 2026-09-01: this repository does not contain the licensed Terminal-Bench source
task corpus or an existing transform contract to build against. Adding a script that only creates
an `admin/` directory would be a placeholder, not a provenance-preserving transform.

That is intentional for the current release-hardening pass. The headline claims are backed by the
model, the license-clean HVTB detector reproduction, the Docker harness evidence, the c13 floor
probe, and the Arm B trace scanner. None of those claims depends on a transform from base
Terminal-Bench tasks into HVTB-form tasks.

A real transform would need to:

1. Start from a licensed Terminal-Bench task source.
2. Add the HVTB-style `admin/` answer-key material without changing the task's normal solution path.
3. Inject detector wiring in a way that can be tested fail-open and fail-closed.
4. Emit provenance metadata tying the transformed task back to its licensed source.
5. Ship tests proving the transform preserves task behavior and does not introduce hidden detector
   reads during setup.

Until those pieces exist, `transform/` is documentation only and must not be cited as completed
work.
