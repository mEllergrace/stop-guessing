"""Stable artifact identity.

**Fixes #15.** Identity was `f"art_{abs(hash(path)) % 10**8}"`. Python salts `hash()` on a str per
interpreter, and every hook invocation is a fresh interpreter, so the same file got a new identity
on every call. Three consecutive processes on one path produced `art_41200995`, `art_50600253`,
`art_38392605`.

That broke first-touch detection, distinct-artifact counting, taint depth, declassification by id,
and every artifact id printed in a denial. Worse, it made CLAIM-07's cross-process proof pass for
the wrong reason: four reads of four *distinct-looking* artifacts drove `taint_depth` to 4, so the
egress was denied by accident rather than by accumulation.

Identity here is a digest over a canonical identity, so it is stable across processes, machines and
reboots — and two names for the same file resolve to the same artifact:

- symlinks and `..` are resolved
- a trailing slash, `./` prefix and duplicate separators are normalised
- on the same host, the inode identity is folded in when it can be read, so a hardlink pair is one
  artifact rather than two
- content digest is recorded but deliberately NOT part of the identity: editing a file must not
  create a new artifact, or a taint would be shed by touching the file
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from stop_guessing.artifacts.digest import bytes_digest, file_digest

ID_PREFIX = "art"
ID_LEN = 16


def canonical_path(path: str | os.PathLike) -> str:
    """The path form two different spellings of one file must agree on."""
    p = Path(os.path.expanduser(str(path)))
    try:
        return str(p.resolve(strict=False))
    except (OSError, RuntimeError):  # pragma: no cover - loop or unreadable parent
        return os.path.normpath(str(p.absolute()))


def _fs_identity(path: str) -> str | None:
    """`dev:ino`, when it can be read. Folds hardlinks together on one host."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    return f"{st.st_dev}:{st.st_ino}"


def artifact_id(path: str | os.PathLike, *, use_fs_identity: bool = True) -> str:
    """A stable id for this artifact.

    Deterministic across processes: same canonical path in, same id out, always.
    """
    canon = canonical_path(path)
    material = canon
    if use_fs_identity:
        fs = _fs_identity(canon)
        if fs:
            # Bound to the path too, so a recycled inode cannot silently inherit a history.
            material = f"{canon}\x00{fs}"
    return f"{ID_PREFIX}_{bytes_digest(f'sg-artifact-v1:{material}'.encode())[:ID_LEN]}"


@dataclass(frozen=True)
class Identity:
    """Everything known about one artifact's identity at one moment."""

    artifact_id: str
    path: str
    canonical_path: str
    fs_identity: str | None
    content_digest: str | None
    exists: bool

    def to_dict(self) -> dict:
        return {
            "artifact_id": self.artifact_id,
            "path": self.path,
            "canonical_path": self.canonical_path,
            "fs_identity": self.fs_identity,
            "digest": self.content_digest,
            "exists": self.exists,
        }


def identify(path: str | os.PathLike, *, digest_content: bool = True) -> Identity:
    """Resolve an artifact's identity, optionally digesting its bytes.

    Content digesting is opt-out because it costs a read, and a PreToolUse gate runs on every tool
    call. The digest belongs in the record; the identity must not depend on it.
    """
    canon = canonical_path(path)
    exists = os.path.exists(canon)
    return Identity(
        artifact_id=artifact_id(path),
        path=str(path),
        canonical_path=canon,
        fs_identity=_fs_identity(canon),
        content_digest=file_digest(canon) if (digest_content and exists) else None,
        exists=exists,
    )
