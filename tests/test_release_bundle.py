"""The release bundle must be verifiable by someone who is not us, and must not overclaim.

`independently_reproduced` is the one assurance axis this repository cannot set about itself. The
bundle does not change that — it removes the excuse. A third party recomputes every subject digest,
runs the suite and the verifier without any key, and reaches their own verdict, including one that
disagrees with ours.

Two properties are load-bearing and both are tested here: it must DETECT a changed byte, and it
must state what it does not establish. A bundle that always says "matches", or that reads as proof
of correctness, would be worse than none.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from release_bundle import build, subject, verify  # noqa: E402

REPO = Path(__file__).resolve().parent.parent


def test_the_subject_covers_the_things_a_verifier_would_check():
    s = subject()
    assert s, "the subject is empty"
    assert "VERSION" in s
    assert "docs/claims.yaml" in s
    assert any(k.startswith("stop_guessing/") and k.endswith(".py") for k in s)
    assert any(k.startswith("stop_guessing/data/") for k in s), "runtime data must be in the subject"
    assert "install.sh" in s


def test_no_pycache_or_generated_noise_in_the_subject():
    assert not [k for k in subject() if "__pycache__" in k]


def test_a_matching_tree_verifies(tmp_path):
    doc = build()
    p = tmp_path / "bundle.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    assert verify(p)["subject_matches"] is True


def test_a_changed_byte_is_detected(tmp_path):
    """The control. A verifier that always says 'matches' establishes nothing."""
    doc = build()
    # Flip one recorded digest — equivalent to a byte changing in the tree.
    key = "VERSION"
    doc["subject"][key] = "0" * 64
    p = tmp_path / "bundle.json"
    p.write_text(json.dumps(doc), encoding="utf-8")

    result = verify(p)
    assert result["subject_matches"] is False
    assert key in result["changed"]


def test_a_removed_file_is_detected(tmp_path):
    doc = build()
    doc["subject"]["stop_guessing/definitely_not_here.py"] = "0" * 64
    p = tmp_path / "bundle.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    assert "stop_guessing/definitely_not_here.py" in verify(p)["missing"]


def test_the_bundle_states_what_it_does_not_establish():
    doc = build()
    text = " ".join(doc["what_this_does_not_establish"]).lower()
    assert "independent reproduction" in text
    assert "correctness" in text
    assert "structural" in text, "the structural-ABSENT caveat must survive into the bundle"
    assert "chain shape only" in text, "a keyless verifier's limit must be stated"


def test_the_bundle_carries_the_axes_including_the_false_one():
    axes = build()["attestation"]["assurance_axes"]
    assert axes["independently_reproduced"] is False, \
        "the axis this repository cannot set must be published as false, not omitted"
    for k in ("executed", "chain_verified", "surface_validated", "control_backed"):
        assert k in axes


def test_the_bundle_reports_the_structural_absent_split():
    audit = build()["audit"]
    assert audit["absent"] == audit["absent_behavioural"] + audit["absent_structural_only"]
    assert audit["absent_structural_only"] > 0, (
        "if this ever reaches zero, every predicate observes behaviour — update the claim rather "
        "than assuming it"
    )


def test_verification_needs_no_key(monkeypatch, tmp_path):
    """A bundle only its author can verify would establish nothing."""
    monkeypatch.delenv("STOP_GUESSING_CHAIN_KEY", raising=False)
    doc = build()
    p = tmp_path / "bundle.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    assert verify(p)["subject_matches"] is True


def test_the_reproduce_steps_name_the_key_requirement_honestly():
    steps = " ".join(build()["reproduce"])
    assert "pytest" in steps and "audit_verify" in steps
    assert "REQUIRES the chain key" in steps, \
        "the one step a stranger cannot run must say so"
