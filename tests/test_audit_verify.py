"""The verifier must reproduce findings that were confirmed by hand.

Thirteen of the 2026-08-04 audit's findings were verified manually against source before this
script existed. Those hand results are the ground truth here: if the predicate disagrees with what
a human read in the file, the predicate is wrong, and a re-verification tool that quietly reports
ABSENT for a defect that is still present is worse than no tool.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from audit_verify import ABSENT, DYNAMIC, FINDINGS, PRESENT, run_all  # noqa: E402

#: Confirmed by hand at commit ad166e8/5177a3e, each by reading the cited file.
HAND_VERIFIED_PRESENT = [
    "SG-HARD-001",  # `surface` absent from runner.check()
    "SG-HARD-002",  # kind_ok = proc is None; has_procedure excluded from proven
    "SG-HARD-004",  # runner.py has zero references to `truncated`
    "SG-HARD-005",  # claims check exit captured then echoed
    "SG-HARD-006",  # LaunchAgent under $HOME, target_uid unused
    "SG-HARD-008",  # hook_post calls ledger.sink.record() directly
    "SG-HARD-015",  # classify_path before identify
    "SG-HARD-034",  # zero .py under the plugin subtree
    "SG-HARD-035",  # no package-data, no MANIFEST.in
    "SG-HARD-041",  # workbook says 20/21
    "SG-HARD-043",  # fill.py hardcodes /Users/isme/...
]

#: Findings this repository has since fixed. Their predicates MUST now report ABSENT.
#:
#: This list is the reconfirmation, and it guards both directions. A finding here that reports
#: PRESENT means a fix was reverted or defeated; a finding in HAND_VERIFIED_PRESENT but not here
#: that reports ABSENT means a predicate has gone blind — which happened twice while this file was
#: being written, both times reporting a live defect as fixed.
FIXED = {
    "SG-HARD-001": "runner._surface_findings() blocks a claim naming an unregistered hook",
    "SG-HARD-002": "proven now requires has_procedure",
    "SG-HARD-004": "chain_ok = intact AND NOT truncated",
    "SG-HARD-005": "claims check exits 0/1/2 and CI propagates 1 and crashes",
    "SG-HARD-047": "cmd_export refuses a truncated prefix",
    "SG-HARD-053": "the page counts current live proofs, not every historical ref",
    # Claim narrowing, 2026-08-04. No feature was removed: bar, --isolated and signed delegation
    # all still work. What changed is what they assert about themselves.
    "SG-HARD-007": "'+isolated' now requires tier >= 2 (a different uid), not tier >= 1",
    "SG-HARD-052": "same-uid tier 1 reports plain 'chain-keyed'",
    "SG-HARD-020": "the gate routes handler output through emit_for_model(); bar gets handle+summary",
    "SG-HARD-039": "the CI no-fetch sub-claim is withdrawn and what CI fetches is enumerated",
    # Evidence-integrity batch, 2026-08-05.
    "SG-HARD-029": "cache filename is a sha256 of the full session id; stored id is verified on load",
    "SG-HARD-031": "write-all loop; torn tail distinguished from corrupted middle and bad UTF-8",
    "SG-HARD-038": "a missing vendored rule records a critical selfcheck instead of continuing",
    "SG-HARD-043": "the rich-text verifier is resolved via $STOP_GUESSING_CAIQ_VERIFIER and a search path",
    "SG-HARD-050": "STOP_GUESSING_DISABLE records a critical disabled-mode transition once per day",
    # Lifecycle batch, 2026-08-05. 9 of 31 events registered, each closing a named evidence gap.
    "SG-HARD-009": "PostToolUseFailure is registered and records the outcome PostToolUse cannot see",
    "SG-HARD-048": "SessionStart/UserPromptSubmit/PreCompact/SubagentStop/Stop/SessionEnd registered",
    "SG-HARD-049": "reconcile() runs at Stop over the turn's dispatches and results",
}


def _by_id(rows):
    return {r["id"]: r for r in rows}


def test_every_finding_has_a_unique_id():
    ids = [f.id for f in FINDINGS]
    assert len(ids) == len(set(ids))


def test_every_finding_names_at_least_one_file():
    for f in FINDINGS:
        assert f.files, f"{f.id} names no evidence location"


def test_hand_verified_findings_are_still_present_unless_fixed():
    """A predicate must not clear a defect nobody fixed."""
    rows = _by_id(run_all())
    for fid in HAND_VERIFIED_PRESENT:
        assert fid in rows, f"{fid} is missing from the finding table"
        if fid in FIXED:
            continue
        assert rows[fid]["status"] == PRESENT, (
            f"{fid} was confirmed by hand, is not in FIXED, but the predicate reports "
            f"{rows[fid]['status']}: {rows[fid]['evidence']}"
        )


def test_every_fixed_finding_reports_absent():
    """The reconfirmation. If a fix is reverted or defeated, this fails."""
    rows = _by_id(run_all())
    for fid, why in FIXED.items():
        assert fid in rows, f"{fid} is missing from the finding table"
        assert rows[fid]["status"] == ABSENT, (
            f"{fid} was fixed ({why}) but its predicate reports {rows[fid]['status']}: "
            f"{rows[fid]['evidence']}"
        )


def test_every_status_is_one_of_the_three():
    for r in run_all():
        assert r["status"] in (PRESENT, ABSENT, DYNAMIC), r


def test_every_result_carries_evidence():
    for r in run_all():
        assert r["evidence"].strip(), f"{r['id']} reported {r['status']} with no evidence"


def test_dynamic_findings_declare_why():
    for r in run_all():
        if r["status"] == DYNAMIC:
            assert any(w in r["evidence"].lower() for w in
                       ("live", "dynamic", "could not", "not located", "no static", "adversarial")), \
                f"{r['id']} is DYNAMIC without saying why: {r['evidence']}"


def test_a_predicate_that_raises_becomes_dynamic_not_absent():
    """A crashed check must never read as 'defect fixed'."""
    from audit_verify import Finding

    def boom():
        raise RuntimeError("predicate exploded")

    f = Finding("SG-TEST-000", "HIGH", "t", ["x"], boom)
    status, evidence = f.run()
    assert status == DYNAMIC
    assert "predicate exploded" in evidence


def test_a_finding_with_no_predicate_is_dynamic_not_absent():
    from audit_verify import Finding

    status, _ = Finding("SG-TEST-001", "HIGH", "t", ["x"]).run()
    assert status == DYNAMIC


def test_filtering_by_id_returns_only_that_finding():
    rows = run_all(["SG-HARD-004"])
    assert len(rows) == 1 and rows[0]["id"] == "SG-HARD-004"


def test_the_table_covers_the_whole_audit():
    """54 findings were published; the table must not quietly drop any."""
    ids = {f.id for f in FINDINGS}
    expected = {f"SG-HARD-{i:03d}" for i in range(1, 55)}
    assert expected - ids == set(), f"missing findings: {sorted(expected - ids)}"
