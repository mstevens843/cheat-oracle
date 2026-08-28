"""Print the predicted truth matrix. `python -m cheat_oracle.model`.

This is the model talking to a human. It reads nothing, runs nothing, and reaches no container;
it renders the pure prediction in ``predict.PREDICTED`` so a reader can see, before any exploit
exists, exactly which detector is predicted to catch which channel and why. The empirical harness
will later print the same shape with an observed column beside the predicted one.
"""

from __future__ import annotations

from .channels import CHANNELS
from .detectors import DETECTORS
from .layers import Verdict
from .predict import PREDICTED, summarize

_SYM = {Verdict.FIRES: "FIRE", Verdict.MISSES: "miss", Verdict.VOID: "VOID"}


def render() -> str:
    lines: list[str] = []
    head = f"{'channel':24}" + "".join(f"{d.id:>6}" for d in DETECTORS)
    lines.append(head)
    lines.append("-" * len(head))
    for ch in CHANNELS:
        row = f"{ch.id} {ch.slug:20}"[:24]
        for d in DETECTORS:
            row += f"{_SYM[PREDICTED[ch.id][d.id].verdict]:>6}"
        lines.append(row)
    lines.append("")
    for d in DETECTORS:
        s = summarize(d)
        tag = "  [TARGET]" if d.is_the_target else "  [FIX]" if d.is_the_fix else ""
        lines.append(
            f"{d.id} {d.slug:14} fires={len(s.fires)} void={len(s.voids)} "
            f"scored-clean={len(s.misses)} {list(s.misses)}{tag}"
        )
    lines.append("")
    lines.append("Legend: FIRE detected, VOID refused-to-certify (fail-closed), "
                 "miss scored 'no hack' (the undercount).")
    return "\n".join(lines)


if __name__ == "__main__":
    print(render())
