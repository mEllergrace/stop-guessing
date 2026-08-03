"""Content addressing.

Ported from spindlebox's `spindlebox/staleness.py`, which already solved file digesting and
drift detection over a tree with tests behind it. Two deliberate changes:

- `file_digest` returns the full sha256, not a prefix. Prefixes are fine for a correlation key
  and wrong for an in-toto subject, which is matched purely by digest.
- Failures return `None` rather than raising, so a snapshot over a partially-readable tree still
  produces a result — but the caller is expected to record the `None` as a known gap rather than
  silently treating the file as absent.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from pathlib import Path

CHUNK = 1 << 20  # 1 MiB


def file_digest(path: str | Path, *, algo: str = "sha256") -> str | None:
    """Full hex digest of a file's bytes, or None if it cannot be read.

    Streams in 1 MiB chunks so a large artifact does not have to fit in memory.
    """
    h = hashlib.new(algo)
    try:
        with open(path, "rb") as fh:
            while chunk := fh.read(CHUNK):
                h.update(chunk)
    except (OSError, ValueError):
        return None
    return h.hexdigest()


def bytes_digest(data: bytes, *, algo: str = "sha256") -> str:
    """Full hex digest of an in-memory payload."""
    return hashlib.new(algo, data).hexdigest()


def snapshot_files(root: str | Path, rel_paths: Iterable[str]) -> dict[str, dict]:
    """Map each relative path to its digest and size.

    An unreadable file gets ``{"digest": None, "size": None, "present": False}`` rather than
    being omitted — the difference between "absent" and "unreadable" is exactly the kind of
    distinction this project exists to preserve.
    """
    root = Path(root)
    out: dict[str, dict] = {}
    for rel in rel_paths:
        p = root / rel
        digest = file_digest(p)
        try:
            size = p.stat().st_size
        except OSError:
            size = None
        out[str(rel)] = {
            "digest": digest,
            "size": size,
            "present": digest is not None,
        }
    return out


def verify_manifest(root: str | Path, manifest: dict[str, str]) -> dict[str, list[str]]:
    """Compare a tree against a ``{relative_path: sha256}`` manifest.

    Returns three named buckets rather than a bare boolean, because "the file changed" and
    "the file vanished" call for different responses.
    """
    root = Path(root)
    ok: list[str] = []
    changed: list[str] = []
    missing: list[str] = []
    for rel, expected in sorted(manifest.items()):
        actual = file_digest(root / rel)
        if actual is None:
            missing.append(rel)
        elif actual == expected:
            ok.append(rel)
        else:
            changed.append(rel)
    return {"ok": ok, "changed": changed, "missing": missing}
