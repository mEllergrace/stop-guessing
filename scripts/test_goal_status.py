#!/usr/bin/env python3
"""Tests for `goal_status.py`.

The one property that matters more than any other here: this script reports on chain keys, and must
never emit key MATERIAL. That is asserted first and directly, because the whole point of reporting
keyids is that they are the disclosable half.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import goal_status as gs  # noqa: E402


def test_it_never_emits_key_material(capsys, monkeypatch):
    """A keyid is disclosable; the key is not. Nothing may print the bytes.

    The env provider is the one that takes material straight from the environment, so it is the
    realistic leak path and is the one exercised here.
    """
    secret = "s3cr3t-key-material-32-bytes-ok!"
    monkeypatch.setenv("STOP_GUESSING_CHAIN_KEY", secret)
    gs.main([])
    out = capsys.readouterr().out
    assert secret not in out
    gs.main(["--json"])
    assert secret not in capsys.readouterr().out


def test_available_keyids_returns_ids_not_material(monkeypatch):
    monkeypatch.setenv("STOP_GUESSING_CHAIN_KEY", "s3cr3t-key-material-32-bytes-ok!")
    ids = gs.available_keyids()
    assert all("s3cr3t" not in i for i in ids)
    assert any(i.startswith("sg-") for i in ids), "no keyid surfaced from the env provider"


def test_a_ledger_whose_key_is_absent_is_reported_as_unavailable(monkeypatch):
    """The #90 situation, which is the reason this script exists."""
    monkeypatch.setattr(gs, "available_keyids", lambda: ["sg-kf-somethingelse"])
    monkeypatch.setattr(gs, "keyid_of_ledger", lambda p: "sg-env-theonethatwrote")
    monkeypatch.setattr(gs, "LEDGERS", ((
        "proofs", Path(__file__), "the proof ledger"),))
    row = gs.key_report()[0]
    assert row["written_under"] == "sg-env-theonethatwrote"
    assert row["key_available"] is False


def test_a_ledger_whose_key_is_present_is_reported_available(monkeypatch):
    monkeypatch.setattr(gs, "available_keyids", lambda: ["sg-env-theonethatwrote"])
    monkeypatch.setattr(gs, "keyid_of_ledger", lambda p: "sg-env-theonethatwrote")
    monkeypatch.setattr(gs, "LEDGERS", ((
        "proofs", Path(__file__), "the proof ledger"),))
    assert gs.key_report()[0]["key_available"] is True


def test_the_exit_code_is_nonzero_only_when_a_key_is_missing(monkeypatch, capsys):
    monkeypatch.setattr(gs, "available_keyids", lambda: ["sg-env-x"])
    monkeypatch.setattr(gs, "keyid_of_ledger", lambda p: "sg-env-x")
    monkeypatch.setattr(gs, "LEDGERS", ((("proofs"), Path(__file__), "p"),))
    assert gs.main([]) == 0
    monkeypatch.setattr(gs, "keyid_of_ledger", lambda p: "sg-env-missing")
    assert gs.main([]) == 1
    capsys.readouterr()


def test_surfaces_are_split_by_whether_a_proof_run_can_drive_them():
    """`plugin`/`skill`/`command` cannot be driven from a proof run — runner.py:540."""
    s = gs.surface_report()
    for surface in s["requires_a_live_session"]:
        assert surface.partition(":")[0] in s["live_session_kinds"]
    for surface in s["driveable_by_a_proof_run"]:
        assert surface.partition(":")[0] not in s["live_session_kinds"]
    assert s["claims"] > 0


def test_every_declared_surface_lands_in_exactly_one_bucket():
    """A surface silently in neither bucket would be an unreported blocker."""
    s = gs.surface_report()
    declared = set()
    for c in gs.runner.load_claims()["claims"]:
        declared.update(str(x) for x in (c.get("surface") or []))
    assert declared == set(s["driveable_by_a_proof_run"]) | set(s["requires_a_live_session"])


def test_json_output_is_valid_and_complete(capsys):
    gs.main(["--json"])
    doc = json.loads(capsys.readouterr().out)
    assert set(doc) == {"keys", "surfaces"}
    assert doc["surfaces"]["claims"] > 0
