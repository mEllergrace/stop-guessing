"""The project page is generated from the attestation, and goes stale loudly."""

from __future__ import annotations

import re

import pytest

from stop_guessing.cli import cmd_page
from stop_guessing.version import repo_root

yaml = pytest.importorskip("yaml")

ATTEST = {
    "proven": 3, "total": 5, "chain_intact": True, "chain_keyed": True, "goal_met": False,
    "aicm_controls_evidenced": {"DSP-20": ["CLAIM-01"], "LOG-10": ["CLAIM-02", "CLAIM-03"]},
    "caiq": {"answers_present": True, "filled_workbooks": ["x.xlsx"], "filled_from_proofs": True},
    "unproven": ["CLAIM-04", "CLAIM-05"],
}
CLAIMS = {"claims": [
    {"id": "CLAIM-01", "statement": "A thing is true.", "proof_kind": "live-run",
     "proofs": ["sg:0:aaaa"]},
    {"id": "CLAIM-04", "statement": "Another thing.", "proof_kind": "negative", "proofs": []},
]}
CAIQ = {"answers": [
    {"control": "DSP-20", "answer": "Yes", "evidence": [{"ref": "sg:0:aaaa"}],
     "claims": ["CLAIM-01"]},
    {"control": "LOG-12", "answer": "No", "evidence": [], "claims": []},
], "proposed_agentic_controls": {"answers": [{"control": "LOG-AG-01", "answer": "Yes",
                                              "evidence": [], "claims": []}]}}


def _page():
    return cmd_page.build(ATTEST, CLAIMS, CAIQ)


def test_numbers_come_from_the_attestation_not_the_template():
    h = _page()
    assert "3/5" in h
    assert "GOAL NOT MET" in h, "a failing attestation must not render as met"


def test_goal_met_renders_only_when_the_attestation_says_so():
    assert "GOAL MET" in cmd_page.build({**ATTEST, "goal_met": True}, CLAIMS, CAIQ)


def test_unproven_claim_shows_zero_proofs():
    h = _page()
    row = re.search(r'CLAIM-04.*?</tr>', h, re.S).group()
    assert ">0<" in row


def test_every_claim_is_rendered():
    h = _page()
    for c in CLAIMS["claims"]:
        assert c["id"] in h


def test_control_coverage_is_rendered_from_the_attestation():
    h = _page()
    assert "DSP-20" in h and "CLAIM-02, CLAIM-03" in h


def test_no_answers_are_not_hidden():
    """A questionnaire of unbroken Yeses is the least believable artifact."""
    h = _page()
    assert 'class="tag no">No' in h


def test_proposed_controls_are_named_as_not_written():
    h = _page()
    assert "LOG-AG-01" in h
    assert "fabrication" in h


def test_statements_are_html_escaped():
    evil = {"claims": [{"id": "CLAIM-X", "statement": "<script>alert(1)</script>",
                        "proof_kind": "live-run", "proofs": []}]}
    h = cmd_page.build(ATTEST, evil, None)
    assert "<script>alert(1)</script>" not in h
    assert "&lt;script&gt;" in h


def test_tags_are_balanced():
    h = _page()
    for tag in ("html", "head", "body", "table", "style", "div"):
        assert len(re.findall(rf"<{tag}[ >]", h)) == len(re.findall(rf"</{tag}>", h)), tag


def test_page_handles_light_and_dark_and_an_explicit_toggle():
    h = _page()
    assert "prefers-color-scheme:dark" in h
    assert 'data-theme="dark"' in h and 'data-theme="light"' in h


def test_wide_content_scrolls_rather_than_breaking_the_page():
    h = _page()
    assert "overflow-x:auto" in h


def test_page_declares_that_it_is_generated():
    assert "page build" in _page() and "Not hand-written" in _page()


def test_committed_page_matches_the_current_attestation():
    """The staleness gate. A page that outlives its evidence is how overclaiming starts."""
    import argparse

    args = argparse.Namespace(keyfile=None)
    committed = (repo_root() / "docs" / "index.html").read_text(encoding="utf-8")
    try:
        expected = cmd_page._render(args)
    except Exception as exc:  # no chain key available in CI
        pytest.skip(f"cannot render: {exc}")
    assert committed == expected, (
        "docs/index.html is stale — run `stop-guessing page build` and commit the result"
    )
