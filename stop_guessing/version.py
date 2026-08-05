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

    NOTE: for RUNTIME DATA (policy, rules) use `data_dir()` instead. This function answers "where
    is the checkout", which is not a question an installed wheel can answer — see #68.
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

    #68 (SG-HARD-035), and worse than the audit reported. This read only ``repo_root()/VERSION``,
    and `repo_root()` falls back to the *package parent* — which under a wheel is `site-packages`,
    where no VERSION exists. `__version__` is evaluated at import, so `import stop_guessing` raised
    outright: the wheel was not merely missing data, it was unimportable. Every developer machine
    hid this because editable installs resolve the checkout, and `install.sh` copied the file by
    hand. Checking the wheel's *contents* did not reveal it either; only installing it into a clean
    interpreter and running it did.

    Checkout first (so a dev tree still wins), then the packaged copy.
    """
    candidates = [repo_root() / "VERSION", Path(__file__).resolve().parent / "data" / "VERSION"]
    tried = []
    for path in candidates:
        tried.append(str(path))
        try:
            raw = path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if not SEMVER.match(raw):
            raise ValueError(f"{path} contains {raw!r}, which is not a bare semver string")
        return raw
    raise ValueError("cannot read VERSION. Searched:\n  " + "\n  ".join(tried))


__version__ = read_version()


def data_dir() -> Path:
    """Where the shipped runtime data lives — policy sets, classification rules, VERSION.

    #68 (SG-HARD-035). These files were resolved as ``repo_root() / "policy"`` and
    ``repo_root() / "rules"``, which works only when a repository checkout exists. `pyproject.toml`
    declared ``packages = ["stop_guessing*"]`` and no package data, and there was no `MANIFEST.in`,
    so a normal wheel shipped none of them. Editable installs from the checkout masked this
    completely: every developer machine worked, and `install.sh` copied the extras by hand, which
    hid the broken distribution path rather than fixing it.

    The data now lives inside the package at ``stop_guessing/data`` and is declared as package
    data, so a wheel carries it. The old top-level locations are still honoured first when they
    exist, so a checkout, an existing deployment, or anything outside this repo that pointed at
    them keeps working.
    """
    packaged = Path(__file__).resolve().parent / "data"
    root = repo_root()
    # Checkout layout first (it is the editable/dev case and must keep winning), then the wheel.
    for candidate in (root, packaged):
        if (candidate / "policy").is_dir() or (candidate / "rules").is_dir():
            return candidate
    return packaged


def policy_dir() -> Path:
    """The default policy set directory."""
    return data_dir() / "policy" / "coc.policy.d"


def rules_dir() -> Path:
    """The default classification/redaction rules directory."""
    return data_dir() / "rules"
