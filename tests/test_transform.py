"""The transform is a prototype contract, not a full Terminal-Bench corpus transform."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from cheat_oracle import transform

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "transform"


def test_transform_adds_admin_detector_wiring_and_provenance(tmp_path: Path) -> None:
    source = FIXTURE / "source-task"
    answer_key = FIXTURE / "answer-key.txt"
    out = tmp_path / "out"

    result = transform.transform_task(
        source,
        out,
        answer_key,
        task_id="synthetic-transform-fixture",
    )

    assert (out / "instruction.md").read_text() == (source / "instruction.md").read_text()
    assert (out / "admin" / "key.txt").read_text() == answer_key.read_text()
    assert (out / "detector" / "hvtb_inotify_watch.sh").exists()
    assert (out / "detector" / "verify_fail_open.sh").exists()
    provenance = json.loads((out / "provenance.json").read_text())
    assert provenance == result.provenance
    assert provenance["schema"] == transform.SCHEMA
    assert provenance["source"]["tree_sha256"] == transform.sha256_tree(source)
    assert provenance["answer_key"]["sha256"] == transform.sha256_file(answer_key)
    assert provenance["not_full_terminal_bench_transform"] is True


def test_transform_preserves_the_synthetic_task_behavior(tmp_path: Path) -> None:
    out = tmp_path / "out"
    transform.transform_task(
        FIXTURE / "source-task",
        out,
        FIXTURE / "answer-key.txt",
        task_id="synthetic-transform-fixture",
    )
    subprocess.run(["bash", "solution.sh"], cwd=out, check=True)
    subprocess.run(["bash", "tests/test.sh"], cwd=out, check=True)


def test_transform_refuses_to_overwrite_existing_output_without_force(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    try:
        transform.transform_task(
            FIXTURE / "source-task",
            out,
            FIXTURE / "answer-key.txt",
            task_id="synthetic-transform-fixture",
        )
    except FileExistsError:
        pass
    else:
        raise AssertionError("transform overwrote an existing output without --force")
