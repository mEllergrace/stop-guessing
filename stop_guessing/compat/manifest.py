"""Integrity of the vendored no-noodles tree.

The vendored copy is only meaningful if it is provably unmodified. `MANIFEST.sha256` pins every
file; `verify()` is called by CI and by `stop-guessing doctor`, and a mismatch is a finding rather
than something to auto-repair — a silently "fixed" vendor tree is exactly how a fork happens
without anyone deciding to fork.
"""

from __future__ import annotations

from pathlib import Path

from stop_guessing.artifacts.digest import file_digest, verify_manifest

MANIFEST_NAME = "MANIFEST.sha256"


def vendored_dir() -> Path:
    return Path(__file__).resolve().parent / "nonoodles"


def _tracked(root: Path) -> list[str]:
    return sorted(p.name for p in root.iterdir() if p.is_file() and p.name != MANIFEST_NAME)


def generate() -> str:
    """Produce `MANIFEST.sha256` content in the standard `<digest>  <name>` shape."""
    root = vendored_dir()
    lines = []
    for name in _tracked(root):
        digest = file_digest(root / name)
        if digest is None:
            raise OSError(f"cannot digest vendored file: {name}")
        lines.append(f"{digest}  {name}")
    return "\n".join(lines) + "\n"


def write() -> Path:
    path = vendored_dir() / MANIFEST_NAME
    path.write_text(generate(), encoding="utf-8")
    return path


def load() -> dict[str, str]:
    path = vendored_dir() / MANIFEST_NAME
    manifest: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        digest, _, name = line.partition("  ")
        manifest[name] = digest
    return manifest


def verify() -> dict:
    """Compare the vendored tree against its manifest.

    Also reports files present on disk but absent from the manifest — an unlisted file in a
    vendor tree is as much a drift as a changed one.
    """
    root = vendored_dir()
    manifest = load()
    result = verify_manifest(root, manifest)
    on_disk = set(_tracked(root))
    result["untracked"] = sorted(on_disk - set(manifest))
    result["intact"] = not (result["changed"] or result["missing"] or result["untracked"])
    return result
