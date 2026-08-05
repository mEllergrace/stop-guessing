"""Alias-based classification bypass — SG-HARD-015 (#56).

The gate classified the path SPELLING the caller supplied and canonicalised only afterwards, for
identity. So a benignly named symlink to a credential classified as public, and its contents
entered model context; `PostToolUse` canonicalises, which is after the bytes were read.

The property asserted here is monotonicity: an alias can only ever ADD labels. If any spelling of
an artifact is classified, the call is classified.
"""

from __future__ import annotations

import os

import pytest

from stop_guessing.cli import gate


@pytest.fixture
def profile(tmp_path, monkeypatch):
    cfg = tmp_path / "claude"
    (cfg / "stop-guessing" / "ledger").mkdir(parents=True)
    key = cfg / "stop-guessing" / "chain.key"
    key.write_bytes(b"a-test-key-that-is-32-bytes-ok!!")
    key.chmod(0o600)
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(cfg))
    monkeypatch.delenv("STOP_GUESSING_CHAIN_KEY", raising=False)
    return cfg


@pytest.fixture
def credential(tmp_path):
    """A file whose real path is classified, under a name that is not."""
    secret_dir = tmp_path / ".ssh"
    secret_dir.mkdir()
    real = secret_dir / "id_rsa"
    real.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n", encoding="utf-8")
    link = tmp_path / "public.txt"
    os.symlink(real, link)
    return real, link


def test_the_real_path_is_classified(credential):
    from stop_guessing.artifacts.classify import classify_path

    real, _ = credential
    assert classify_path(str(real)).classified, "fixture is wrong if this fails"


def test_the_alias_spelling_alone_is_not_classified(credential):
    """The premise of the bypass: the benign name looks benign."""
    from stop_guessing.artifacts.classify import classify_path

    _, link = credential
    assert not classify_path(str(link)).classified


def test_reading_through_the_alias_is_classified_anyway(profile, credential):
    """The fix, asserted on observable behaviour: the alias now produces a decision."""
    _, link = credential
    d = gate.decide({"tool_name": "Read", "tool_input": {"file_path": str(link)},
                     "session_id": "s1"}, posture="steer")
    assert d is not None, "a classified target reached through an alias produced no decision"
    assert d["outcome"] == "ask", f"expected an ask on first touch, got {d['outcome']}"


def test_the_aliasing_itself_reaches_the_ledger(profile, credential):
    """Resolving it silently would hide the attempt; the RECORD must show it."""
    import json

    real, link = credential
    gate.decide({"tool_name": "Read", "tool_input": {"file_path": str(link)},
                 "session_id": "s1"}, posture="steer")
    led = profile / "stop-guessing" / "ledger" / "custody.jsonl"
    rec = json.loads(led.read_text(encoding="utf-8").splitlines()[-1])
    blob = json.dumps(rec)
    assert "path aliasing" in blob, "the alias was resolved but left no trace in the record"
    assert str(link) in blob and str(real) in blob


def test_joining_is_monotone_labels_are_never_lost():
    from stop_guessing.artifacts.classify import Classification

    a = Classification(labels=frozenset({"public"}), matched=("m1",), sources=("s1",))
    b = Classification(labels=frozenset({"restricted", "pii"}), matched=("m2",), sources=("s2",))
    joined = gate._join_classification(a, b)
    assert joined.labels == {"public", "restricted", "pii"}
    assert set(joined.sources) == {"s1", "s2"}


def test_a_direct_read_of_the_real_path_still_works(profile, credential):
    """The fix must not change behaviour for the ordinary, non-aliased case."""
    real, _ = credential
    import json

    d = gate.decide({"tool_name": "Read", "tool_input": {"file_path": str(real)},
                     "session_id": "s2"}, posture="steer")
    assert d is not None and d["outcome"] == "ask"
    led = profile / "stop-guessing" / "ledger" / "custody.jsonl"
    rec = json.loads(led.read_text(encoding="utf-8").splitlines()[-1])
    assert "path aliasing" not in json.dumps(rec), "no alias was used, so none should be recorded"


def test_dot_dot_traversal_to_a_classified_path_is_caught(profile, credential):
    real, _ = credential
    sneaky = str(real.parent / ".." / ".ssh" / "id_rsa")
    d = gate.decide({"tool_name": "Read", "tool_input": {"file_path": sneaky},
                     "session_id": "s3"}, posture="steer")
    assert d is not None and d["outcome"] == "ask"


def test_an_unresolvable_path_does_not_take_the_call_down(profile, tmp_path):
    """Robustness: a broken symlink must not raise out of the gate."""
    broken = tmp_path / "dangling"
    os.symlink(tmp_path / "nope", broken)
    gate.decide({"tool_name": "Read", "tool_input": {"file_path": str(broken)},
                 "session_id": "s4"}, posture="steer")  # must not raise
