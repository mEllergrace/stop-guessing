"""The hygiene detector and the path rewriter must agree on what is deliberate.

`scripts/depersonalise_paths.py` refuses to rewrite `IMPLEMENTATION_PLAN.md`, `CHANGELOG.md` and
`IMPLEMENTATION_LOG.md`, because those record what was changed and rewriting them would falsify the
record. `scripts/hygiene_sweep.py` counted `CHANGELOG.md` as a finding anyway — so one script called
a file protected while the other called it a defect, and the "0 findings" number flipped to 1 the
moment a changelog entry did its job and named the path it removed.

Two tools disagreeing about the same policy is how a suppression sneaks in disguised as a fix. This
pins the agreement.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import depersonalise_paths as dp  # noqa: E402
import hygiene_sweep as hs  # noqa: E402


def test_every_protected_file_is_also_excused_by_the_detector():
    missing = [f for f in dp.SKIP if f not in hs.DELIBERATE]
    assert not missing, (
        f"the rewriter protects {missing} while the sweep counts them as findings; one of the two "
        "is wrong and the number means nothing until they agree")


def test_every_excused_record_file_is_also_protected_from_rewriting():
    """The other direction: excusing a file from the count while still rewriting it would be worse.

    Only the historical-record files are checked — the two `depersonalise_paths` sources are excused
    because they hold the literals by nature, not because they are records.
    """
    records = {"IMPLEMENTATION_PLAN.md", "CHANGELOG.md", "IMPLEMENTATION_LOG.md"}
    for f in records:
        assert f in hs.DELIBERATE, f"{f} is not excused by the sweep"
        assert f in dp.SKIP, f"{f} is excused from the count but still gets rewritten"


def test_every_excuse_states_a_reason():
    """An entry with no reason is a suppression. The reason is what makes it reviewable."""
    for name, why in hs.DELIBERATE.items():
        assert isinstance(why, str) and len(why) > 25, f"{name} is excused without a real reason"


def test_the_excused_files_actually_exist():
    """A stale excuse silently widens over time as files are renamed."""
    for name in hs.DELIBERATE:
        assert (REPO / name).is_file(), f"{name} is excused but does not exist"


def test_the_sweep_reports_zero_findings_in_shipped_files():
    """The end state this is all for, asserted rather than read off a terminal.

    If this fails, either a real hardcoded path was introduced or something was excused that should
    have been fixed — and the test above requires every excuse to carry a reason.
    """
    result = hs.sweep(REPO)
    real, _deliberate, _ignored = hs._triage(result["hardcoded_paths"], REPO)
    assert real == {}, f"hardcoded paths in shipped files: {sorted(real)}"
    assert not result["vendored_dirs"], f"tracked vendor dirs: {result['vendored_dirs']}"
    sd = result["stale_docs"] or {}
    assert not (sd.get("version_drift") or {}), sd["version_drift"]
    assert not (sd.get("not_started_claims") or {}), sd["not_started_claims"]
