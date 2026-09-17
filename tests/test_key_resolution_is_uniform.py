"""Every surface resolves the chain key the same way, or a keyed ledger reads as unkeyed.

#61 and #66 both landed this fix in one place at a time: `hook_gate`, then three CLI
commands, each gaining the same comment -- "discover(), not from_env(): an installed
profile keeps its key in a mode-600 keyfile". Two call sites were missed, and on a
profile whose key lives in a keyfile the consequences were:

    CLAIM-21   "no chain key -- answers derived from an unverifiable ledger are not
               answers", so the claim could never be proved and `attest --self` could
               never report GOAL MET
    page build  the same, silently weaker

A fix applied by hand at each call site is a fix that keeps being incomplete, so this
scans for the pattern instead. `from_env` remains a legitimate TIER inside
`attest/keys.py`, which is what `discover` composes.
"""

from __future__ import annotations

import re
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent.parent / "stop_guessing"
CALL = re.compile(r"\bfrom_env\(")


def test_no_surface_resolves_the_chain_key_from_the_environment_alone() -> None:
    offenders = []
    for path in sorted(PACKAGE.rglob("*.py")):
        if path.parent.name == "attest" and path.name == "keys.py":
            continue  # the tier itself, composed by discover()
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if CALL.search(line) and not line.lstrip().startswith("#"):
                offenders.append(f"{path.relative_to(PACKAGE.parent)}:{number}: {line.strip()}")
    assert not offenders, (
        "these resolve the chain key from the environment only, so a keyed profile whose "
        "key lives in a keyfile reads as unkeyed:\n  " + "\n  ".join(offenders))
