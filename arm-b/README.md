# Arm B - retroactive undercount over real HVTB traces

Drop Harbor trial directories under `traces/<trial>/`, each in the Harbor layout:

    traces/<trial>/agent/trajectory.json   (or .jsonl / .txt - scanned as text)
    traces/<trial>/verifier/reward.txt     (reward <= --clean-reward means scored clean)

Then run:

    uv run python -m cheat_oracle.harness.arm_b --key-path admin/

The scanner applies the channel model to each trial the HVTB detector scored as no-hack and reports
how many obtained the answer key through a channel the admin/ directory watch does not observe - the
retroactive undercount, receipted to `evidence/arm-b.json`.

STATUS: gated. The 2,225 released HVTB traces are on Harbor hub and were not shared with this account
(`harbor download` reports no access; the hub lists no HVTB job). With no traces here the scanner
reports GATED and writes no evidence. See ../DISCLOSURE.md.
