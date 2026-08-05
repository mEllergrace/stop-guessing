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

#: UN-CLAIMED, 2026-08-05, round 2. SG-HARD-006 was listed here and is not fixed.
#:
#: I claimed a tier-2 LaunchDaemon install. The round-2 audit established it could not work in four
#: independent ways — an unassigned $CLAUDE_DIR fatal under `set -u`, an interpreter path
#: (runtime/bin/python) that `pip --target` never creates, no --keyfile so the daemon exits 2, and
#: a service account with no traversal through the 0700 user-owned parent. The predicate that
#: cleared it was satisfied by the string "/Library/LaunchDaemons" appearing in the file.
#:
#: The installer now stages the plist and states plainly that tier 2 is NOT installed. Removing the
#: entry from FIXED is the point of this list: a claim withdrawn is more useful than a claim
#: defended, and this harness catching my own retraction is it working.
#:
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
    # Packaging, 2026-08-05. The wheel was not merely missing data — it could not import.
    "SG-HARD-035": "runtime data ships inside the package; a clean-venv wheel install runs",
    # CAIQ epoch, 2026-08-05. The release attestation is excluded from both the count it states
    # and the evidence it cites, so the loop reaches a fixpoint instead of drifting by one.
    "SG-HARD-041": "CLAIM-21 is a release attestation, counted in neither the epoch nor the evidence",
    "SG-HARD-054": "the workbook epoch and the attestation agree and the scope is stated",
    "SG-HARD-015": "both the supplied spelling and its canonical target are classified and joined",
    "SG-HARD-010": "the daemon reads and records peer credentials and admits by uid",
    "SG-HARD-011": "op_append validates and refuses before sequencing",
    "SG-HARD-017": "policy authorises before any handler or its test executes",
    "SG-HARD-023": "an unverifiable ledger never falls back to the agent-writable cache",
    "SG-HARD-024": "_record_gap uses key discovery, so gaps record against a keyed ledger",
    "SG-HARD-012": "doctor passes settings and pinned registration in, and queries daemon state",
    "SG-HARD-033": "one resolver for the ledger path, and the key is chosen by the ledger's keyid",
    "SG-HARD-040": "fill re-derives in memory and refuses on any field-level disagreement",
    "SG-HARD-016": "identity is the logical path; the inode is observed, not identifying",
    "SG-HARD-030": "seal archives the segment and opens a new one chained to its seal",
    "SG-HARD-046": "the exporter emits an OTLP envelope with integer enums and real ids",
    "SG-HARD-008": "PostToolUse routes through recorder.client and records a loss as critical",
    "SG-HARD-044": "the verdict is reported on five axes, not collapsed into one boolean",
    "SG-HARD-045": "CLAIM-20 checks a declared expectation per surface, not rc in {0,1}",
    "SG-HARD-003": "each proof binds the policy/rules/interpreter it exercised; drift kills the ref",
    "SG-HARD-013": "managed.json floors the posture and ledger protection outside project reach",
    "SG-HARD-014": "the loaded policy set is checked against a managed expected digest",
    "SG-HARD-032": "digest-pinned verified prefix plus a per-connection read deadline",
    "SG-HARD-034": "hooks run a launcher in the plugin root that pins the interpreter",
    "SG-HARD-051": "regimes are assessed over applicable record kinds; empty is not a pass",
    "SG-HARD-021": "delegated execution runs under an OS capability boundary, self-tested",
    # Settled by live adversarial tests, 2026-08-05. Three of these were CONFIRMED by the attack
    # before they were fixed: the hostile paired test, the TOCTOU race, and the multi-artifact call.
    "SG-HARD-018": "the script is digested before its test runs; a rewrite is refused",
    "SG-HARD-019": "execution runs an immutable snapshot, not the mutable pathname",
    "SG-HARD-022": "decide() holds a per-session lock across state read, decision and append",
    "SG-HARD-025": "replay skips denied effects, dedupes paired records, keeps all outputs",
    "SG-HARD-026": "a content digest is bound at result time with its remaining window stated",
    "SG-HARD-027": "every classified input in a call is recorded, not only the worst",
    "SG-HARD-028": "the detector states that it is advisory and names the enforced boundary",
    "SG-HARD-036": "the runtime is built fresh, health-checked and swapped in, never merged",
    "SG-HARD-037": "settings.json is temp-written, fsynced, renamed, and backed up",
    "SG-HARD-042": "the answers document is re-derived and compared field by field",
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
