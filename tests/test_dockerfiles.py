"""Guards for Docker reproducibility promises made in README/RESULTS.

These are host-only checks. They do not prove the images build, but they prevent the base images
from drifting back to floating or tag-only references after the release-hardening pass.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILES = (
    ROOT / "images" / "subject" / "Dockerfile",
    ROOT / "images" / "monitor" / "Dockerfile",
    ROOT / "images" / "floor" / "Dockerfile",
)
DEBIAN_BOOKWORM_SLIM = "sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171"
PYTHON_312_SLIM_BOOKWORM = (
    "sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2"
)
EXPECTED_FROM = {
    ROOT / "images" / "subject" / "Dockerfile": (
        f"FROM debian:bookworm-slim@{DEBIAN_BOOKWORM_SLIM}"
    ),
    ROOT / "images" / "floor" / "Dockerfile": (
        f"FROM debian:bookworm-slim@{DEBIAN_BOOKWORM_SLIM}"
    ),
    ROOT / "images" / "monitor" / "Dockerfile": (
        f"FROM python:3.12.13-slim-bookworm@{PYTHON_312_SLIM_BOOKWORM}"
    ),
}


def _from_lines(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text().splitlines()
        if line.startswith("FROM ")
    ]


def test_docker_base_images_are_digest_pinned() -> None:
    digest = re.compile(r"^FROM [^@\s]+@sha256:[0-9a-f]{64}$")
    for path in DOCKERFILES:
        lines = _from_lines(path)
        assert lines, f"{path} has no FROM line"
        assert all(digest.match(line) for line in lines), f"{path}: {lines}"


def test_docker_base_image_digests_match_the_release_note() -> None:
    for path, expected in EXPECTED_FROM.items():
        assert _from_lines(path) == [expected]


def test_dockerfiles_do_not_use_floating_stable_or_minor_python_tags() -> None:
    banned = ("debian:stable", "stable-slim", "python:3.12-slim")
    for path in DOCKERFILES:
        text = path.read_text()
        found = [tag for tag in banned if tag in text]
        assert not found, f"{path} uses floating base tag(s): {found}"
