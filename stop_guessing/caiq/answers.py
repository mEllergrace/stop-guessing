"""Derive AI-CAIQ answers from proofs. Never the other way round.

This is the direction of causation the whole project exists to enforce. The workbook is a
*rendering* of the ledger: for each AICM control, the answer and its implementation text are
computed from the claims that map to that control and the ledger records that proved them. Nobody
writes an answer and then goes looking for evidence — that is the failure
`rockin-robin/docs/PIPELINE-CONFORMANCE-GAP.md` names in its own history: *"that is a STRING IN A
PROMPT, not conformance."*

rockin-robin's four maintenance rules, kept:

- **Every answer carries evidence** — here, verified ledger record ids, not sentences.
- **"No" is legitimate** — a control we do not implement is answered No with the search path
  stated.
- **Unassessed is not "No"** — a control with no mapped claim is simply absent from the output,
  and `fill` leaves those rows EMPTY.
- **Name the right control** — ids are checked against the workbook, and `I&S`/`A&A` keep their
  ampersands.
"""

from __future__ import annotations

from dataclasses import dataclass

from stop_guessing.prove import runner

#: Controls we deliberately answer "No" on, with the search path stated. Honesty is load-bearing:
#: a questionnaire of unbroken Yeses is the least believable artifact an auditor can receive.
NEGATIVE_ANSWERS = {
    "LOG-12": (
        "No. There is artifact-level and decision-level provenance, but no continuous "
        "activity log for cryptographic key lifecycle events specifically. Evidence searched: "
        "stop_guessing/attest/keys.py, stop_guessing/ledger/, rules/, policy/coc.policy.d/."
    ),
    "STA-09": (
        "No. A service Bill of Materials is not emitted. The in-toto Statement envelope and the "
        "pinned MANIFEST.sha256 over the vendored tree are adjacent but are not an SBOM. "
        "Evidence searched: stop_guessing/attest/, stop_guessing/compat/, .github/workflows/."
    ),
}

#: CSA's DRAFT agentic controls, from labs.cloudsecurityalliance.org. They are proposed, not
#: published, and do not exist in the AICM v1.1.0 workbook. Evidence for them is recorded in the
#: answers file and reported by `attest --self`, but they are NEVER written into CSA's
#: questionnaire — inventing rows in a published artifact is precisely the kind of quiet
#: fabrication this toolchain exists to prevent. `fill` refuses them, which is how this was found.
PROPOSED_CONTROLS = frozenset({"IAM-AG-03", "LOG-AG-01", "LOG-AG-02", "AG-GV.2", "AG-GV.3"})


def is_published(control: str) -> bool:
    return control not in PROPOSED_CONTROLS


#: Ownership under CSA's SSRM vocabulary. This ships as an Orchestrated Service Provider component.
DEFAULT_OWNER = "Owned by OSP"

CUSTOMER_RESPONSIBILITY = (
    "Install with `install.sh --all-profiles`, keep the chain key in the OS keychain rather than "
    "the environment, and run `stop-guessing attest --self` before relying on any claim."
)


@dataclass
class DerivedAnswer:
    control: str
    answer: str
    ssrm: str | None
    implementation: str
    evidence: list[str]
    claims: list[str]

    def to_fill(self) -> dict:
        d = {"answer": self.answer, "implementation": self.implementation,
             "customer_responsibilities": CUSTOMER_RESPONSIBILITY}
        if self.ssrm:
            d["ssrm"] = self.ssrm
        return d

    def to_yaml_entry(self) -> dict:
        return {
            "control": self.control,
            "answer": self.answer,
            "ssrm": self.ssrm,
            "implementation": self.implementation,
            "claims": self.claims,
            "evidence": [{"type": "ledger", "ref": r} for r in self.evidence],
        }


#: Claims whose procedure GENERATES this document. They cannot be counted inside it: the proof
#: record does not exist while the procedure that writes the file is still running, so including
#: them guarantees the artifact and the attestation citing it disagree by exactly one. See #74.
RELEASE_ATTESTATION_CLAIMS = frozenset({"CLAIM-21"})


def _app_rows(result: dict) -> list[dict]:
    return [r for r in (result.get("rows") or [])
            if r["id"] not in RELEASE_ATTESTATION_CLAIMS]


def _app_proven(result: dict) -> int:
    return sum(1 for r in _app_rows(result) if r.get("proven"))


def _app_total(result: dict) -> int:
    return len(_app_rows(result))


def derive(key, ledger=None) -> tuple[list[DerivedAnswer], dict]:
    """Compute answers from the claims that are PROVEN, and only those.

    An unproven claim contributes nothing, so a control whose only claim is unproven does not
    appear — which is the "unassessed is not No" rule, mechanically.
    """
    ledger = ledger or runner.DEFAULT_LEDGER
    result = runner.check(key, ledger)
    doc = runner.load_claims()
    by_id = {c["id"]: c for c in doc["claims"]}

    by_control: dict[str, list[dict]] = {}
    for row in result["rows"]:
        if not row["proven"]:
            continue
        # #74, the last of the recursion. A release-attestation claim is the attestation *of* this
        # document, so it cannot also be evidence *in* it: its proof record is written after the
        # file, so any ref it contributed was stale the moment it was cited — which is exactly the
        # "3 evidence refs no longer resolve" finding. Excluding it from the count but leaving it
        # in the evidence would have cut only half the loop.
        if row["id"] in RELEASE_ATTESTATION_CLAIMS:
            continue
        claim = by_id[row["id"]]
        for ctrl in claim.get("aicm") or []:
            by_control.setdefault(ctrl, []).append({"claim": claim, "refs": row["live"]})

    answers: list[DerivedAnswer] = []
    for ctrl, entries in sorted(by_control.items()):
        claims = [e["claim"]["id"] for e in entries]
        refs = sorted({r for e in entries for r in e["refs"]})
        if ctrl in NEGATIVE_ANSWERS:
            answers.append(DerivedAnswer(ctrl, "No", DEFAULT_OWNER,
                                         NEGATIVE_ANSWERS[ctrl], refs, claims))
            continue
        statements = "; ".join(
            e["claim"]["statement"].strip().rstrip(".") for e in entries
        )
        impl = (
            f"{statements}. Proven by {len(refs)} record(s) in this toolchain's own keyed "
            f"chain-of-custody ledger ({', '.join(refs)}), each produced by an executable "
            f"procedure and re-verified by `stop-guessing claims check`."
        )
        answers.append(DerivedAnswer(ctrl, "Yes", DEFAULT_OWNER, impl, refs, claims))

    for ctrl in NEGATIVE_ANSWERS:
        if ctrl not in by_control:
            answers.append(DerivedAnswer(ctrl, "No", DEFAULT_OWNER,
                                         NEGATIVE_ANSWERS[ctrl], [], []))

    answers.sort(key=lambda a: a.control)
    return answers, result


def split_published(answers: list[DerivedAnswer]) -> tuple[list, list]:
    """Published AICM v1.1.0 controls, and CSA's proposed agentic ones. Only the first get filled."""
    return ([a for a in answers if is_published(a.control)],
            [a for a in answers if not is_published(a.control)])


def to_yaml_doc(answers: list[DerivedAnswer], result: dict) -> dict:
    published, proposed = split_published(answers)
    return {
        "meta": {
            "generated_by": "stop-guessing caiq derive",
            "note": (
                "DERIVED from proofs. Do not hand-edit: every answer is computed from the claims "
                "that are proven in the ledger, and every evidence ref is a ledger record id that "
                "`stop-guessing claims check` re-verifies. Editing this file by hand reverses the "
                "direction of causation the toolchain exists to enforce."
            ),
            # #74 (SG-HARD-041). This reported `proven/total` over ALL claims, including the
            # release-attestation claim whose own procedure generates this file. That claim's
            # proof record does not exist yet while it is running, so the workbook was written
            # saying N-1/N and the attestation that cited it then said N/N — two artifacts of
            # the same run permanently disagreeing, with no re-run able to reconcile them:
            # regenerating afterwards changes the digest and invalidates the proof that bound it.
            #
            # The recursion is cut by counting only the APPLICATION claims. The release
            # attestation is reported separately, as the thing that produced this document rather
            # than as one of the facts inside it.
            "claims_proven": f"{_app_proven(result)}/{_app_total(result)}",
            "claims_scope": (
                "APPLICATION claims only. The release-attestation claim "
                f"({', '.join(RELEASE_ATTESTATION_CLAIMS)}) derives and fills this document, so "
                "it cannot appear in a count this document states — its proof record does not "
                "exist until after this file is written. It is reported by "
                "`stop-guessing attest --self`, not here."
            ),
            "release_attestation": sorted(RELEASE_ATTESTATION_CLAIMS),
            "published_controls_answered": len(published),
            "proposed_controls_recorded": len(proposed),
            "chain_intact": result["chain_intact"],
            "chain_keyed": result["chain_keyed"],
            "aicm_version": "1.1.0",
            "caiq_version": "1.1.0",
        },
        "answers": [a.to_yaml_entry() for a in published],
        "proposed_agentic_controls": {
            "note": (
                "CSA's DRAFT agentic controls (labs.cloudsecurityalliance.org). Proposed, not "
                "published: they do not exist in the AICM v1.1.0 workbook and are NOT written "
                "into it. Recorded here because the evidence is real and the gap analysis is "
                "CSA's own, but presenting them as AICM controls would be a fabrication."
            ),
            "answers": [a.to_yaml_entry() for a in proposed],
        },
    }
