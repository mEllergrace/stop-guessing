"""Ledger IO under damage — SG-HARD-031 (#64).

A crash can only ever damage the LAST line of an append-only file. Anything else is someone
editing it. The loader used to call both "truncated", which describes tampering in the vocabulary
of an accident, and it read the file as text so one bad byte made the whole ledger unreadable.
"""

from __future__ import annotations

import os

import pytest

from stop_guessing.ledger.chain import ChainKey
from stop_guessing.ledger.sink import LedgerError, load, record

KEY = ChainKey("test-key", b"a-test-key-that-is-32-bytes-ok!!")


@pytest.fixture
def ledger(tmp_path):
    p = tmp_path / "custody.jsonl"
    for i in range(4):
        record(p, {"op": "artifact.read", "actor": "test", "severity": "info",
                   "at": f"2026-08-05T10:00:{i:02d}.000Z", "detail": f"r{i}"}, KEY)
    return p


# ── short writes ─────────────────────────────────────────────────────────────


def test_a_short_write_is_looped_not_silently_truncated(tmp_path, monkeypatch):
    """os.write is DOCUMENTED to write fewer bytes than asked. One unchecked call tears a line."""
    real_write = os.write
    state = {"first": True}

    def stingy(fd, data):
        # Write one byte the first time, then behave. Without a loop this produces a torn record.
        if state["first"]:
            state["first"] = False
            return real_write(fd, bytes(data)[:1])
        return real_write(fd, data)

    monkeypatch.setattr(os, "write", stingy)
    p = tmp_path / "short.jsonl"
    record(p, {"op": "artifact.read", "actor": "t", "severity": "info",
               "at": "2026-08-05T10:00:00.000Z"}, KEY)
    monkeypatch.undo()

    loaded = load(p, KEY)
    assert not loaded.truncated, "the write loop must have completed the line"
    assert not loaded.corrupt
    assert len(loaded.entries) == 1
    assert loaded.chain.intact


def test_a_write_that_makes_no_progress_raises_rather_than_tearing(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "write", lambda fd, data: 0)
    with pytest.raises(LedgerError, match="short write"):
        record(tmp_path / "stuck.jsonl", {"op": "artifact.read", "actor": "t",
                                          "severity": "info", "at": "2026-08-05T10:00:00.000Z"}, KEY)


# ── torn tail vs corrupted middle ────────────────────────────────────────────


def test_a_torn_final_line_is_truncated_not_corrupt(ledger):
    with ledger.open("a", encoding="utf-8") as fh:
        fh.write('{"op": "artifact.read", "act')      # no trailing newline: an interrupted write
    loaded = load(ledger, KEY)
    assert loaded.truncated is True
    assert loaded.corrupt is False
    assert loaded.malformed_at is None
    assert len(loaded.entries) == 4, "the intact prefix is still evidence"


def test_an_unparseable_middle_line_is_corruption_not_truncation(ledger):
    lines = ledger.read_text(encoding="utf-8").splitlines()
    lines[1] = "{ this is not json"
    ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")

    loaded = load(ledger, KEY)
    assert loaded.corrupt is True
    assert loaded.malformed_at == 2
    assert loaded.truncated is False, "a crash cannot damage a line that is not the last one"


def test_a_complete_final_line_that_is_garbage_is_corruption(ledger):
    """Ends with a newline, so the writer finished. Garbage means something else wrote it."""
    with ledger.open("a", encoding="utf-8") as fh:
        fh.write("not json at all\n")
    loaded = load(ledger, KEY)
    assert loaded.corrupt is True
    assert loaded.truncated is False


def test_invalid_utf8_reports_one_damaged_line_instead_of_raising(ledger):
    with ledger.open("ab") as fh:
        fh.write(b"\xff\xfe not text\n")
    loaded = load(ledger, KEY)          # must not raise
    assert loaded.decode_error_at == 5
    assert loaded.corrupt is True
    assert len(loaded.entries) == 4, "records before the damage are still returned"


# ── refusing to append onto damage ───────────────────────────────────────────


def test_append_refuses_a_corrupted_middle_and_says_so_in_those_words(ledger):
    lines = ledger.read_text(encoding="utf-8").splitlines()
    lines[1] = "{ tampered"
    ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(LedgerError, match="CORRUPTED"):
        record(ledger, {"op": "artifact.read", "actor": "t", "severity": "info",
                        "at": "2026-08-05T11:00:00.000Z"}, KEY)


def test_append_refuses_invalid_utf8(ledger):
    with ledger.open("ab") as fh:
        fh.write(b"\xff\xfe\n")
    with pytest.raises(LedgerError, match="not valid UTF-8"):
        record(ledger, {"op": "artifact.read", "actor": "t", "severity": "info",
                        "at": "2026-08-05T11:00:00.000Z"}, KEY)


def test_usable_is_false_for_every_kind_of_damage(ledger):
    assert load(ledger, KEY).usable is True
    with ledger.open("a", encoding="utf-8") as fh:
        fh.write('{"torn')
    assert load(ledger, KEY).usable is False


def test_a_clean_ledger_is_usable_and_reports_no_damage(ledger):
    loaded = load(ledger, KEY)
    assert loaded.usable and not loaded.corrupt and not loaded.truncated
    assert loaded.malformed_at is None and loaded.decode_error_at is None
