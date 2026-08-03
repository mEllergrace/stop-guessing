"""The every-run version gate, and the copy-only invariant.

These tests build their own workbooks. None of them opens the real CSA template for writing, and
`test_inspection_never_modifies_the_source` asserts that reading it leaves digest *and* mtime
untouched — the mechanical form of "copy it, never change it".
"""

from __future__ import annotations

import json

import pytest

from stop_guessing.artifacts.digest import file_digest
from stop_guessing.caiq.workbook import (
    EXPECTED_DIMENSIONS,
    EXPECTED_SHEET,
    WorkbookError,
    inspect,
    template_record,
)
from stop_guessing.version import repo_root

openpyxl = pytest.importorskip("openpyxl")

GOOD_A1 = json.dumps(
    {
        "specification_name": "AI Controls Matrix",
        "specification_version": "1.1.0",
        "caiq_version": "1.1.0",
    }
)


def _workbook(tmp_path, a1=GOOD_A1, sheet=EXPECTED_SHEET, rows=324, cols=12):
    """A minimal stand-in with the same shape as the real template."""
    wb = openpyxl.Workbook()
    wb.remove(wb.active)
    wb.create_sheet("Introduction")
    ws = wb.create_sheet(sheet)
    wb.create_sheet("LLM Taxonomy")
    wb.create_sheet("Change Log")
    ws.cell(1, 1).value = a1
    ws.cell(rows, cols).value = "end"
    p = tmp_path / "wb.xlsx"
    wb.save(p)
    return p


# ── the gate ─────────────────────────────────────────────────────────────────


def test_clean_workbook_has_no_findings(tmp_path):
    ins = inspect(_workbook(tmp_path))
    assert ins.ok, ins.findings
    assert ins.specification_version == "1.1.0"
    assert ins.caiq_version == "1.1.0"
    assert ins.dimensions == EXPECTED_DIMENSIONS


def test_version_comes_from_a1_not_the_sheet_name(tmp_path):
    """The whole point. Sheet name unchanged, A1 drifted — every existing consumer would pass."""
    a1 = json.dumps(
        {
            "specification_name": "AI Controls Matrix",
            "specification_version": "1.0.2",
            "caiq_version": "1.0.2",
        }
    )
    ins = inspect(_workbook(tmp_path, a1=a1))
    assert ins.data_sheet == EXPECTED_SHEET, "sheet name is still the expected one"
    assert not ins.ok
    assert any("specification_version is '1.0.2'" in f for f in ins.findings)


def test_empty_a1_is_a_finding(tmp_path):
    ins = inspect(_workbook(tmp_path, a1=None))
    assert not ins.ok
    assert any("A1 is empty" in f for f in ins.findings)


def test_non_json_a1_is_a_finding(tmp_path):
    ins = inspect(_workbook(tmp_path, a1="AI-CAIQ v1.1.0"))
    assert not ins.ok
    assert any("not JSON" in f for f in ins.findings)


def test_wrong_specification_name_is_a_finding(tmp_path):
    a1 = json.dumps({"specification_name": "Cloud Controls Matrix", "specification_version": "1.1.0"})
    ins = inspect(_workbook(tmp_path, a1=a1))
    assert any("specification_name" in f for f in ins.findings)


def test_missing_expected_sheet_is_a_finding(tmp_path):
    ins = inspect(_workbook(tmp_path, sheet="AI-CAIQv1.0.2"))
    assert not ins.ok
    assert ins.data_sheet is None
    assert any("not present" in f for f in ins.findings)


def test_wrong_dimensions_is_a_finding(tmp_path):
    ins = inspect(_workbook(tmp_path, rows=100))
    assert any("dimensions" in f for f in ins.findings)


def test_missing_workbook_raises_rather_than_guessing(tmp_path):
    with pytest.raises(WorkbookError, match="no workbook"):
        inspect(tmp_path / "absent.xlsx")


def test_inspection_returns_findings_rather_than_raising(tmp_path):
    """Drift must still produce a record — the caller decides what refuses."""
    ins = inspect(_workbook(tmp_path, a1="garbage"))
    assert isinstance(ins.findings, list) and ins.findings
    assert ins.digest is not None


# ── copy-only ────────────────────────────────────────────────────────────────


def test_inspection_never_modifies_the_source(tmp_path):
    p = _workbook(tmp_path)
    before_digest = file_digest(p)
    before_mtime = p.stat().st_mtime_ns
    for _ in range(3):
        inspect(p)
        template_record(p)
    assert file_digest(p) == before_digest, "inspection modified the workbook"
    assert p.stat().st_mtime_ns == before_mtime, "inspection touched the workbook's mtime"


def test_template_json_is_committed_and_matches_the_pinned_expectation():
    """`reference/TEMPLATE.json` is what makes the gate work without shipping CSA's file."""
    p = repo_root() / "docs" / "ai-caiq" / "reference" / "TEMPLATE.json"
    assert p.is_file(), "TEMPLATE.json must be committed — it pins the template we never ship"
    rec = json.loads(p.read_text(encoding="utf-8"))
    assert rec["specification_name"] == "AI Controls Matrix"
    assert rec["specification_version"] == "1.1.0"
    assert rec["caiq_version"] == "1.1.0"
    assert rec["data_sheet"] == EXPECTED_SHEET
    assert rec["dimensions"] == EXPECTED_DIMENSIONS
    assert len(rec["sha256"]) == 64
    assert rec["sheet_names"] == ["Introduction", "AI-CAIQv1.1.0", "LLM Taxonomy", "Change Log"]
    assert "COPY-ONLY" in rec["_note"]


def test_template_json_carries_the_csa_vocabularies():
    p = repo_root() / "docs" / "ai-caiq" / "reference" / "TEMPLATE.json"
    rec = json.loads(p.read_text(encoding="utf-8"))
    assert rec["valid_answers"] == ["Yes", "No", "NA"], "CSA's vocabulary has no 'Partial'"
    assert rec["editable_columns"] == [3, 4, 5, 6], "only columns C-F are answerable"
    assert "Shared across the supply chain" in rec["valid_owners"]


def test_blank_template_xlsx_is_not_committed():
    """It is a local backup of a CSA artifact, cited and never redistributed from here."""
    ref = repo_root() / "docs" / "ai-caiq" / "reference"
    assert not list(ref.glob("*.xlsx")), "the blank template must not be committed"
