"""The published framework posture must not claim more than the benchmark measured.

`docs/frameworks.yaml` is the source of record for what this toolchain is measured against. It is
publishable precisely because it is checkable: every `externally-validated` row has to correspond to
a validator that actually ran and actually rejected a broken input, and the `not-benchmarked` rows
have to carry a reason.

The failure this guards is the one the README already committed: listing ISO/IEC 27037, SEC 17a-4(f)
and FRE 902 in one "Standards" row, so a reader concludes three frameworks were tested when one was a
single-clause schema source, one an untested design target, and one never exercised at all.
"""

from __future__ import annotations

import sys

import pytest
import yaml

from stop_guessing.version import repo_root

REPO = repo_root()
sys.path.insert(0, str(REPO / "scripts"))

TIERS = {"externally-validated", "self-asserted", "mapped", "design-target",
         "not-benchmarked", "out-of-scope"}

DOC = yaml.safe_load((REPO / "docs" / "frameworks.yaml").read_text(encoding="utf-8"))
FRAMEWORKS = DOC["frameworks"]


def _by_tier(tier):
    return [f for f in FRAMEWORKS if f["tier"] == tier]


def test_every_framework_has_a_known_tier():
    for f in FRAMEWORKS:
        assert f["tier"] in TIERS, f"{f['id']}: unknown tier {f['tier']!r}"
        assert f.get("name") and f.get("id")


def test_every_externally_validated_row_names_a_validator_and_a_control():
    """A validator with no control is not validation — it may accept anything."""
    rows = _by_tier("externally-validated")
    assert rows, "no framework claims external validation"
    for f in rows:
        assert f.get("validator") and f["validator"] != "none obtainable", \
            f"{f['id']} claims external validation with no validator"
        assert f.get("control"), f"{f['id']} claims external validation with no control case"
        assert f.get("evidence"), f"{f['id']} claims external validation with no evidence ref"


def test_the_benchmark_agrees_with_the_externally_validated_claims():
    """The load-bearing test: the published tier must match what the validator actually returned.

    If a validator stops being obtainable, the row must drop to self-asserted — not stay green
    because the YAML says so.
    """
    from benchmark_frameworks import run

    measured = run()
    by_format = {r["format"]: r for r in measured["results"]}

    expected = {"case-uco": "CASE/UCO JSON-LD",
                "otlp": "OTLP JSON (traces)",
                "w3c-prov": "W3C PROV-JSON"}
    for fid, fmt in expected.items():
        row = next(f for f in FRAMEWORKS if f["id"] == fid)
        result = by_format.get(fmt)
        assert result, f"the benchmark does not measure {fmt}"
        if result["status"] == "unavailable":
            pytest.skip(f"{fmt} validator unavailable here: {result['detail']}")
        assert result["status"] == "pass", (
            f"{fid} is published as externally-validated but the benchmark says "
            f"{result['status']}: {result['detail']}")
        assert row["tier"] == "externally-validated"


def test_no_row_claims_validation_the_benchmark_reports_as_untested():
    """in-toto is the live case: installed, but exposing no Statement validator."""
    from benchmark_frameworks import run

    untested = set(run()["unavailable"])
    if "in-toto Statement v1" in untested:
        row = next(f for f in FRAMEWORKS if f["id"] == "in-toto")
        assert row["tier"] == "self-asserted", (
            "in-toto has no obtainable validator, so it cannot be published as externally validated")


def test_every_not_benchmarked_row_says_why():
    """A named absence is a decision; an unnamed one reads as an oversight."""
    rows = _by_tier("not-benchmarked")
    assert len(rows) >= 8, "the not-benchmarked list looks suspiciously short"
    for f in rows:
        assert len(f.get("why", "") or f.get("what", "")) > 30, f"{f['id']} is absent without a reason"


def test_out_of_scope_rows_say_why_too():
    for f in _by_tier("out-of-scope"):
        assert len(f.get("why", "")) > 40, f"{f['id']} is excluded without a stated reason"


def test_every_not_benchmarked_row_carries_a_review_trigger():
    """A standards choice with no review condition becomes the constraint the next reader inherits.

    This is the same failure as the hand-written status block, one level up: prose written once, true
    then, and load-bearing forever. A TRIGGER survives contact with time in a way a date does not —
    "re-evaluate when ISO/IEC 42006 settles" still means something in two years.
    """
    for f in _by_tier("not-benchmarked"):
        assert len(f.get("review", "")) > 15, f"{f['id']} has no review trigger"


def test_the_ranking_is_total_and_puts_42001_first():
    """42001 leads because it is the standard CSA is looking at for Level 2 STAR for AI listings.

    That is a live certification path, not a nice-to-have, so the ordering is asserted rather than
    left to reading order.
    """
    rows = _by_tier("not-benchmarked")
    priorities = [f.get("priority") for f in rows]
    assert all(isinstance(x, int) for x in priorities), "an unranked framework cannot be prioritised"
    assert len(set(priorities)) == len(priorities), f"duplicate priorities: {priorities}"
    first = min(rows, key=lambda f: f["priority"])
    assert first["id"] == "iso-42001", f"expected 42001 first, got {first['id']}"
    assert "STAR" in first["why"], "the 42001 row does not say why it leads"


def test_42001_does_not_claim_a_tool_can_be_certified():
    """A management-system standard certifies an ORGANISATION, never a piece of software.

    "42001 compliant" printed next to a tool name would be precisely the overclaim this file exists
    to prevent, so the row has to carry the limit explicitly.
    """
    row = next(f for f in FRAMEWORKS if f["id"] == "iso-42001")
    limit = row.get("scope_limit", "")
    assert limit, "the 42001 row states no scope limit"
    assert "cannot be certified" in limit or "cannot be" in limit
    assert "organisation" in limit.lower()


def test_a_demoted_recommendation_records_what_replaced_it():
    """27041 was recommended first and demoted. The reversal must be legible, not silently corrected."""
    row = next(f for f in FRAMEWORKS if f["id"] == "iso-27041")
    alts = row.get("alternatives_considered", "")
    assert "demoted" in alts, "the demotion of 27041 is not recorded"
    assert "iso-15026" in alts or "15026" in alts


def test_the_frameworks_a_reviewer_would_demand_are_all_present():
    """Named explicitly so silence about any of them becomes a test failure, not an omission."""
    ids = {f["id"] for f in FRAMEWORKS}
    for required in ("iso-42001", "iso-15026", "nist-cftt", "iso-27041", "acpo", "eu-ai-act-12",
                     "slsa", "daubert", "iso-27037", "sec-17a-4f", "fre-902", "aicm", "case-uco",
                     "w3c-prov"):
        assert required in ids, f"{required} is not addressed at all"


def test_the_aicm_row_states_its_denominator():
    """A control count read as coverage is the overclaim; the denominator prevents it."""
    row = next(f for f in FRAMEWORKS if f["id"] == "aicm")
    assert "243" in row["result"], "the AICM row does not say how many controls exist"
    assert "not" in row["result"].lower()
    assert len(row["controls"]) == 14


def test_fre_902_is_marked_unexercised():
    """The certification path exists and nobody has ever signed. That must be visible."""
    row = next(f for f in FRAMEWORKS if f["id"] == "fre-902")
    assert "UNEXERCISED" in row["result"] or "unexercised" in row["result"]


def test_daubert_records_that_we_currently_fail_it():
    """The user's goal is that this be scientifically defensible. Daubert is that test."""
    row = next(f for f in FRAMEWORKS if f["id"] == "daubert")
    assert "fails it" in row["why"] or "currently fails" in row["why"]
