"""Integrity guard the model's docstring promised but nothing enforced: every modelled channel has
a runnable program, and every program is a modelled channel. Without it, a declaration with no
script (or a script with no declaration) fails only at container-run time, never in the unit suite.
Pure - it reads the filesystem layout, touches no container.
"""

from __future__ import annotations

from pathlib import Path

from cheat_oracle.model.channels import CHANNEL_IDS

_CHANNELS_DIR = Path(__file__).resolve().parents[1] / "images" / "subject" / "harness" / "channels"


def _script_ids() -> set[str]:
    return {p.stem for p in _CHANNELS_DIR.glob("c*.sh")}


def test_every_channel_has_a_script() -> None:
    missing = set(CHANNEL_IDS) - _script_ids()
    assert not missing, f"modelled channels with no channels/<id>.sh: {sorted(missing)}"


def test_every_script_is_a_modelled_channel() -> None:
    extra = _script_ids() - set(CHANNEL_IDS)
    assert not extra, f"channel scripts with no model declaration: {sorted(extra)}"
