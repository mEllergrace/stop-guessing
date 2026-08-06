"""Tests for the path de-personalisation, written and passing before it rewrites tracked source."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import depersonalise_paths as dp  # noqa: E402


def test_the_replacement_preserves_the_classification_rule():
    """The whole reason this is safe: the label comes from the path STRING, not the file."""
    from stop_guessing.artifacts.classify import classify_path

    before = classify_path("/Users/isme/work/CSA/roster.csv")
    after = classify_path("/example/work/CSA/roster.csv")
    assert after.labels == before.labels, (
        f"de-personalising changed the classification: {sorted(before.labels)} -> "
        f"{sorted(after.labels)}")
    assert after.classified, "the synthetic fixture path no longer classifies as sensitive"


def test_the_replacement_target_does_not_exist_anywhere():
    """A synthetic fixture that happens to exist would read as a real file to a reviewer."""
    assert not Path("/example/work/CSA/roster.csv").exists()


def test_scan_finds_a_personal_path(tmp_path):
    f = tmp_path / "x.py"
    f.write_text('p = "/Users/isme/work/CSA/roster.csv"\n', encoding="utf-8")
    assert dp.scan([f])


def test_scan_is_quiet_on_clean_source(tmp_path):
    """The control: a scanner that always reports would rewrite the whole tree."""
    f = tmp_path / "x.py"
    f.write_text('p = "/example/work/CSA/roster.csv"\n', encoding="utf-8")
    assert dp.scan([f]) == {}


def test_rewrite_replaces_only_the_prefix(tmp_path):
    f = tmp_path / "x.py"
    f.write_text('p = "/Users/isme/work/CSA/roster.csv"  # keep this comment\n', encoding="utf-8")
    dp.rewrite([f])
    out = f.read_text(encoding="utf-8")
    assert "/example/work/CSA/roster.csv" in out
    assert "/Users/isme" not in out
    assert "# keep this comment" in out, "the rewrite damaged surrounding text"


def test_rewrite_is_idempotent(tmp_path):
    f = tmp_path / "x.py"
    f.write_text('p = "/Users/isme/work/CSA/roster.csv"\n', encoding="utf-8")
    dp.rewrite([f])
    once = f.read_text(encoding="utf-8")
    assert dp.rewrite([f]) == {}
    assert f.read_text(encoding="utf-8") == once


def test_the_vendored_tree_is_never_rewritten():
    """Vendored means byte-identical to upstream. Rewriting it would silently fork it."""
    assert not [p for p in dp.candidates()
                if "compat/nonoodles" in str(p)], "the vendored tree is a rewrite candidate"


def test_the_planning_record_is_not_falsified():
    """IMPLEMENTATION_PLAN.md deliberately records where each reused asset was found.

    Rewriting those paths would make the provenance record say something that was never true, which
    is the opposite of what this repository is for.
    """
    rels = {str(p.relative_to(dp.REPO)) for p in dp.candidates()}
    for protected in ("IMPLEMENTATION_PLAN.md", "IMPLEMENTATION_LOG.md", "CHANGELOG.md"):
        assert protected not in rels


def test_references_to_other_checkouts_are_reported_not_guessed():
    """hygiene_sweep.py hardcoded a path to another checkout, so it worked for one person.

    The right value depends on the operator's layout, so it is named rather than invented.
    """
    roots = dp.other_local_roots()
    assert isinstance(roots, dict)
    for hits in roots.values():
        assert all(":" in h for h in hits), "a finding must carry its line number"
