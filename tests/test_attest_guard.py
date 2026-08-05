"""The guard must catch a regression it was not told to look for.

These tests are hermetic — they never invoke the real attestation or touch the real ledger. A
guard whose test depends on production state is the failure documented at runner.py:274, where a
test asserting "the goal is not met before the workbook exists" started passing for the wrong
reason the moment the real workbook appeared.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from attest_guard import compare, snapshot_of  # noqa: E402


def _attestation(**over) -> dict:
    """A passing attestation, before any deliberate damage."""
    base = {
        "chain_intact": True,
        "chain_keyed": True,
        "chain_reason": None,
        "total": 3,
        "proven": 3,
        "ok": True,
        "goal_met": True,
        "rows": [
            {"id": "CLAIM-01", "proven": True, "live": ["sg:1:aaa"]},
            {"id": "CLAIM-02", "proven": True, "live": ["sg:2:bbb"]},
            {"id": "CLAIM-03", "proven": True, "live": ["sg:3:ccc"]},
        ],
        "caiq": {"workbook_digest_bound": True, "filled_from_proofs": True,
                 "answers_present": True, "findings": []},
        "aicm_controls_evidenced": {"DSP-20": ["CLAIM-01"], "LOG-03": ["CLAIM-02"]},
    }
    base.update(over)
    return base


def test_identical_snapshots_report_no_regression():
    s = snapshot_of(_attestation())
    assert compare(s, s) == []


def test_a_claim_becoming_unproven_is_caught():
    before = snapshot_of(_attestation())
    damaged = _attestation()
    damaged["rows"][1]["proven"] = False
    damaged["proven"] = 2
    damaged["ok"] = False
    regressions = compare(before, snapshot_of(damaged))
    assert any("CLAIM-02" in r for r in regressions), regressions


def test_a_broken_chain_is_caught():
    before = snapshot_of(_attestation())
    after = snapshot_of(_attestation(chain_intact=False, chain_reason="hash mismatch at 57"))
    regressions = compare(before, after)
    assert any("chain" in r.lower() for r in regressions), regressions


def test_losing_the_key_is_caught():
    """A keyed ledger silently becoming unkeyed is a downgrade, not a neutral change."""
    before = snapshot_of(_attestation())
    after = snapshot_of(_attestation(chain_keyed=False))
    assert any("keyed" in r.lower() for r in compare(before, after))


def test_losing_an_evidenced_control_is_caught():
    """AICM coverage is the deliverable; dropping a control is a regression even if claims pass."""
    before = snapshot_of(_attestation())
    after = snapshot_of(_attestation(aicm_controls_evidenced={"DSP-20": ["CLAIM-01"]}))
    assert any("LOG-03" in r for r in compare(before, after))


def test_workbook_binding_lost_is_caught():
    before = snapshot_of(_attestation())
    after = _attestation()
    after["caiq"] = dict(after["caiq"], workbook_digest_bound=False)
    assert any("workbook" in r.lower() for r in compare(before, snapshot_of(after)))


def test_improvement_is_never_reported_as_regression():
    """A guard that blocks progress gets disabled, and then it guards nothing."""
    before = snapshot_of(_attestation(proven=2, goal_met=False, ok=False,
                                      caiq={"workbook_digest_bound": False,
                                            "filled_from_proofs": False,
                                            "answers_present": True, "findings": []}))
    after = snapshot_of(_attestation())
    assert compare(before, after) == []


def test_a_claim_appearing_is_not_a_regression():
    before = snapshot_of(_attestation())
    grown = _attestation()
    grown["rows"].append({"id": "CLAIM-04", "proven": True, "live": ["sg:4:ddd"]})
    grown["total"] = 4
    grown["proven"] = 4
    assert compare(before, snapshot_of(grown)) == []


def test_snapshot_records_the_claims_individually_not_just_the_count():
    """One claim breaking while another is added nets to zero on a count. It is still a break."""
    before = snapshot_of(_attestation())
    swapped = _attestation()
    swapped["rows"][0]["proven"] = False
    swapped["rows"].append({"id": "CLAIM-04", "proven": True, "live": ["sg:4:ddd"]})
    swapped["total"] = 4
    regressions = compare(before, snapshot_of(swapped))
    assert any("CLAIM-01" in r for r in regressions), regressions
