"""Version resolution.

The `VERSION` file at the repository root is the single source of truth. Every other version
string in the project — `pyproject.toml`, `plugin.json`, `marketplace.json`, the install stamp —
is generated from it, and `tests/test_version.py` asserts they agree.

rich-text already demonstrates the failure this prevents: its `plugin.json` says 0.2.14 while its
`manifest.yaml` says 0.3.0, because both are hand-maintained.
"""

from __future__ import annotations

import re
from pathlib import Path

SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


def repo_root() -> Path:
    """The repository root, found by walking up for the VERSION file.

    Falls back to the package parent so an installed (non-editable) copy still resolves.
    """
    here = Path(__file__).resolve()
    for candidate in here.parents:
        if (candidate / "VERSION").is_file():
            return candidate
    return here.parent.parent


def read_version() -> str:
    """Return the semver string in VERSION.

    Raises ValueError rather than guessing: an unreadable or malformed version is a fault, and
    a tool whose whole purpose is provenance must not invent its own version number.
    """
    path = repo_root() / "VERSION"
    try:
        raw = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    if not SEMVER.match(raw):
        raise ValueError(f"{path} contains {raw!r}, which is not a bare semver string")
    return raw


__version__ = read_version()
