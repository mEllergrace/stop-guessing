"""The single-writer recorder, and the boundary it actually provides.

Until the daemon existed, every isolation claim above tier 0 was aspirational: the "recorder" was
library code in the agent's own process, under the agent's own uid, with the chain key in the
agent's own environment. These tests assert what the daemon really buys, and — just as
importantly — that the tier is derived from what is true rather than asserted.
"""

from __future__ import annotations

import os
import threading
import time

import pytest

from stop_guessing.attest.keys import ChainKey
from stop_guessing.ledger.chain import verify
from stop_guessing.ledger.sink import load
from stop_guessing.recorder import client, daemon

KEY = ChainKey("rec", b"recorder-test-key-32-bytes-long!")


@pytest.fixture
def running(tmp_path):
    cfg = tmp_path / "claude"
    ready = threading.Event()
    server = daemon.serve(cfg, key=KEY, ready=ready)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    ready.wait(5)
    for _ in range(50):
        if client.daemon_info(cfg):
            break
        time.sleep(0.05)
    yield cfg
    server.shutdown()
    server.server_close()
    daemon.socket_path(cfg).unlink(missing_ok=True)


def _event(i=0):
    return {"op": "artifact.read", "at": "t", "actor": "a", "detail": str(i)}


# ── it runs, and reports itself honestly ─────────────────────────────────────


def test_daemon_answers_ping(running):
    info = client.daemon_info(running)
    assert info["ok"] and info["keyed"] and info["pid"] == os.getpid()


def test_tier_is_derived_not_asserted(running):
    tier, why = client.isolation_tier(running)
    assert tier == 1, "same uid is tier 1, and must not report itself as 2"
    assert "same uid" in why


def test_tier_zero_when_no_daemon(tmp_path):
    tier, why = client.isolation_tier(tmp_path / "claude")
    assert tier == 0 and "no recorder daemon" in why


# ── key separation, which is the point ───────────────────────────────────────


def test_a_caller_with_no_key_still_produces_a_keyed_record(running):
    out = client.append(running, _event(), fallback_key=None)
    assert out.ref and out.isolation_tier == 1 and out.via == "daemon"
    entries = load(daemon.ledger_path(running), KEY).entries
    assert entries[0]["hash_alg"] == "hmac-sha256"
    assert verify(entries, KEY).intact, "the record must verify under the key the CALLER lacked"


def test_the_caller_cannot_choose_its_own_sequence_or_predecessor(running):
    """A recorded party that could set these could insert itself anywhere in history."""
    client.append(running, _event(0))
    forged = {**_event(1), "seq": 999, "prev_hash": "0" * 64, "hash": "f" * 64,
              "hash_alg": "sha256", "keyid": "mine"}
    client.append(running, forged)
    entries = load(daemon.ledger_path(running), KEY).entries
    assert [e["seq"] for e in entries] == [0, 1]
    assert all(e["hash_alg"] == "hmac-sha256" for e in entries)
    assert verify(entries, KEY).intact


# ── single writer ────────────────────────────────────────────────────────────


def test_concurrent_callers_produce_one_contiguous_chain(running):
    import concurrent.futures as cf

    with cf.ThreadPoolExecutor(max_workers=12) as ex:
        list(ex.map(lambda i: client.append(running, _event(i)), range(60)))
    entries = load(daemon.ledger_path(running), KEY).entries
    assert [e["seq"] for e in entries] == list(range(60))
    assert verify(entries, KEY).intact


# ── it fails closed on integrity, open on availability ───────────────────────


def test_absent_daemon_falls_back_and_records_the_tier(tmp_path):
    cfg = tmp_path / "claude"
    out = client.append(cfg, _event(), fallback_key=KEY)
    assert out.ref and out.isolation_tier == 0 and out.via == "in-process"
    entry = load(daemon.ledger_path(cfg), KEY).entries[0]
    assert any("isolation tier 0" in g for g in entry["known_gaps"]), (
        "a fallback write must say so in the record, never silently"
    )


def test_daemon_refuses_to_append_onto_a_broken_chain(running):
    import json

    client.append(running, _event(0))
    led = daemon.ledger_path(running)
    lines = led.read_text().splitlines()
    d = json.loads(lines[0])
    d["detail"] = "TAMPERED"
    led.write_text(json.dumps(d, sort_keys=True, separators=(",", ":")) + "\n")
    out = client.append(running, _event(1))
    assert out.ref is None and "bury the break" in (out.error or "")


def test_a_refusal_is_not_laundered_by_the_fallback(running):
    """If the daemon refuses on integrity, falling back to a direct write would undo the refusal."""
    import json

    client.append(running, _event(0))
    led = daemon.ledger_path(running)
    d = json.loads(led.read_text().splitlines()[0])
    d["detail"] = "TAMPERED"
    led.write_text(json.dumps(d, sort_keys=True, separators=(",", ":")) + "\n")
    before = len(led.read_text().splitlines())
    client.append(running, _event(1), fallback_key=KEY)
    assert len(led.read_text().splitlines()) == before, "the refusal was laundered by a fallback"


# ── state derived by the party that owns the history ─────────────────────────


def test_the_daemon_derives_custody_state(running):
    client.append(running, {
        "op": "artifact.read", "at": "t", "actor": "a", "session_id": "s1",
        "resources": {"used": [{"artifact_id": "a1", "path": "/x/roster.csv",
                                "digest": "sha256:x", "labels": ["restricted", "pii"]}]}})
    st = client.custody_state(running, "s1")
    assert st["depth"] == 1 and "restricted" in st["labels"] and st["digest"]


def test_state_is_refused_when_the_chain_is_broken(running):
    import json

    client.append(running, {"op": "artifact.read", "at": "t", "session_id": "s1"})
    led = daemon.ledger_path(running)
    d = json.loads(led.read_text().splitlines()[0])
    d["op"] = "artifact.write"
    led.write_text(json.dumps(d, sort_keys=True, separators=(",", ":")) + "\n")
    assert client.custody_state(running, "s1") is None, (
        "state derived from a broken chain is worthless and must not be served"
    )


# ── protocol hygiene ─────────────────────────────────────────────────────────


def test_malformed_request_does_not_kill_the_recorder(running):
    import socket as s

    with s.socket(s.AF_UNIX, s.SOCK_STREAM) as c:
        c.connect(str(daemon.socket_path(running)))
        c.sendall(b"this is not json\n")
        c.makefile("rb").readline(65536)
    assert client.daemon_info(running), "the daemon died on a malformed request"


def test_unknown_op_is_rejected_not_ignored(running):
    resp = client._request(running, {"op": "delete_everything"})
    assert resp and not resp["ok"] and "unknown op" in resp["error"]


def test_socket_is_not_world_writable(running):
    import stat as st

    mode = daemon.socket_path(running).stat().st_mode
    assert not (mode & st.S_IWOTH), "a world-writable recorder socket is not a boundary"


def test_a_second_daemon_refuses_to_bind(running):
    with pytest.raises(OSError, match="already listening"):
        daemon.serve(running, key=KEY)


def test_stale_socket_is_reclaimed(tmp_path):
    cfg = tmp_path / "claude"
    sock = daemon.socket_path(cfg)
    sock.parent.mkdir(parents=True, exist_ok=True)
    sock.touch()  # a leftover from a killed daemon
    server = daemon.serve(cfg, key=KEY)
    try:
        assert daemon.socket_path(cfg).exists()
    finally:
        server.server_close()
        sock.unlink(missing_ok=True)
