"""The filer must be idempotent and must not overstate what it filed.

It runs again after fixes land. If it duplicates on re-run the tracker becomes useless at exactly
the moment it is being used most, and if it files a DYNAMIC inference as a confirmed defect it
launders an unverified claim into a record — the causation this project exists to reverse.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from audit_verify import DYNAMIC, PRESENT  # noqa: E402
from file_audit_issues import body_for, plan, title_for  # noqa: E402


def test_titles_are_prefixed_with_the_finding_id():
    """The id prefix is what makes re-runs idempotent."""
    for row in plan():
        assert title_for(row).startswith(row["id"] + ":")


def test_titles_are_unique():
    titles = [title_for(r) for r in plan()]
    assert len(titles) == len(set(titles))


def test_only_present_and_dynamic_are_filed():
    """A fixed finding must not be filed as an open defect."""
    for row in plan():
        assert row["status"] in (PRESENT, DYNAMIC)


def test_a_confirmed_finding_says_it_was_re_derived():
    """Skips once nothing is PRESENT — reaching zero is the goal, not a test failure.

    Written against a synthetic row rather than `next(...)` on a live plan, so the wording is
    still asserted after the last real finding is fixed. A test that only holds while defects
    exist stops protecting the thing it was written for at exactly the moment it matters.
    """
    row = next((r for r in plan() if r["status"] == PRESENT), None) or {
        "id": "SG-HARD-001", "severity": "CRITICAL", "title": "synthetic",
        "status": PRESENT, "evidence": "synthetic evidence for the wording assertion",
    }
    body = body_for(row, "abc1234")
    assert "CONFIRMED PRESENT" in body
    assert "re-derived from source" in body


def test_a_dynamic_finding_is_filed_as_unverified():
    rows = [r for r in plan() if r["status"] == DYNAMIC]
    if not rows:
        return
    body = body_for(rows[0], "abc1234")
    assert "UNVERIFIED" in body
    assert "inference" in body
    assert "CONFIRMED PRESENT" not in body


def test_every_body_carries_evidence_and_a_recheck_command():
    for row in plan():
        body = body_for(row, "abc1234")
        assert row["evidence"][:40] in body, f"{row['id']} body lacks its evidence"
        assert f"audit_verify.py --id {row['id']}" in body


def test_every_body_names_the_commit_it_was_verified_at():
    """Holds when nothing is left to file, which is the state this whole effort was aiming at."""
    row = (plan() or [None])[0] or {
        "id": "SG-HARD-001", "severity": "CRITICAL", "title": "synthetic",
        "status": PRESENT, "evidence": "synthetic",
    }
    assert "deadbee" in body_for(row, "deadbee")


def test_status_filter_narrows_the_plan():
    """Correct whether or not anything currently matches.

    It briefly asserted that some findings must still be DYNAMIC, which would have failed the
    suite for the good reason — every finding having been settled. A filter's contract is that
    what it returns matches; it is not that the set is non-empty.
    """
    assert all(r["status"] == PRESENT for r in plan("PRESENT"))
    assert all(r["status"] == DYNAMIC for r in plan("DYNAMIC"))
