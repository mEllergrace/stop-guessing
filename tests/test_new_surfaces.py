"""`record emit` and `demo` — the two surfaces I deleted instead of building.

CLAIM-05 declared `cli:"stop-guessing record emit"` and CLAIM-07 declared
`cli:"stop-guessing demo --posture steer"`. Neither existed. Withdrawing the declarations cleared
the gate's finding and made both claims smaller in the same edit — the trade `prove/scope.py` now
catches. These tests cover the surfaces as built.

The load-bearing assertions are the REFUSALS and the CONTROLS. A `record emit` that prints a record
whatever you hand it, or a demo whose tamper-check always says "detected", would be worse than not
having them: they would look like evidence.
"""

from __future__ import annotations

import json
import subprocess
import sys

from stop_guessing.version import repo_root

CLI = [sys.executable, "-m", "stop_guessing.cli.main"]


def run(*argv, **kw):
    return subprocess.run([*CLI, *argv], capture_output=True, text=True,  # noqa: S603
                          cwd=str(repo_root()), timeout=300, **kw)


# ── record emit ──────────────────────────────────────────────────────────────


def test_the_fixture_record_is_valid_and_prints_an_in_toto_statement():
    res = run("record", "emit", "--fixture")
    assert res.returncode == 0, res.stdout + res.stderr
    body = res.stdout[res.stdout.index("{"):res.stdout.rindex("}") + 1]
    stmt = json.loads(body)
    assert stmt["_type"] == "https://in-toto.io/Statement/v1"
    assert stmt["predicateType"].endswith("/Custody/v1")
    assert stmt["predicate"]["alterations"] == []


def test_alterations_empty_is_accepted_as_an_assertion():
    """`[]` says nothing was altered. That is a claim, and it is allowed."""
    assert run("record", "emit", "--fixture").returncode == 0


def test_alterations_absent_is_refused():
    """M2's negative claim. Absent means nobody looked, and that is not writable."""
    res = run("record", "emit", "--fixture", "--omit", "alterations")
    assert res.returncode == 1, res.stdout
    assert "REFUSED" in res.stdout
    assert "alterations (absent)" in res.stdout


def test_known_gaps_absent_is_refused_too():
    res = run("record", "emit", "--fixture", "--omit", "verification.known_gaps")
    assert res.returncode == 1
    assert "known_gaps" in res.stdout


def test_every_tier_a_field_is_actually_enforced():
    """The control against a validator that only checks the two fields I remembered."""
    from stop_guessing.ledger.entry import TIER_A

    for path in TIER_A:
        res = run("record", "emit", "--fixture", "--omit", path)
        assert res.returncode == 1, f"dropping Tier-A field {path} was NOT refused"
        assert path.split(".")[-1] in res.stdout, f"the refusal did not name {path}"


def test_the_refusal_explains_why_rather_than_just_failing():
    out = run("record", "emit", "--fixture", "--omit", "alterations").stdout
    assert "nobody looked" in out
    assert "fails CLOSED" in out


# ── demo ─────────────────────────────────────────────────────────────────────


def test_the_demo_runs_and_cites_a_record_for_every_step():
    res = run("demo", "--posture", "steer")
    assert res.returncode == 0, res.stdout + res.stderr
    out = res.stdout
    for step in ("1.", "2.", "3.", "4.", "5.", "6.", "7."):
        assert step in out, f"step {step} missing from the demo"
    assert out.count("[sg:") >= 4, "steps are not citing record ids"


def test_the_demo_shows_the_ask_then_the_accumulation_deny():
    out = run("demo", "--posture", "steer").stdout
    assert "outcome=ask" in out, "first touch did not ask"
    assert "egress -> deny" in out, "accumulation did not deny"


def test_the_demo_runs_its_own_controls_and_they_pass():
    """Both controls must be present AND passing, or the demo is decoration."""
    out = run("demo", "--posture", "steer").stdout
    assert "egresses freely -> allow" in out, (
        "the clean-session control is missing: 'accumulation denies' would be satisfied by a "
        "policy that denies every egress")
    assert "tampered chain intact=False" in out, "the tamper control did not detect the edit"
    assert "CONTROL FAILED" not in out, out


def test_the_demo_does_not_touch_the_real_ledger():
    from stop_guessing.prove import runner

    before = runner.DEFAULT_LEDGER.read_bytes() if runner.DEFAULT_LEDGER.exists() else b""
    run("demo", "--posture", "steer")
    after = runner.DEFAULT_LEDGER.read_bytes() if runner.DEFAULT_LEDGER.exists() else b""
    assert before == after, "the demo wrote into the evidence ledger"


def test_the_demo_says_it_is_not_a_proof():
    out = run("demo", "--posture", "steer").stdout
    assert "DEMONSTRATION" in out
    assert "prove" in out.lower()


def test_observe_posture_also_runs():
    """`observe` is the default posture in the shipped config; it must not crash."""
    assert run("demo", "--posture", "observe").returncode == 0


def test_the_demo_refuses_without_a_key(monkeypatch):
    """An unkeyed demo would be showing records the recorded party could forge."""
    env = {k: v for k, v in __import__("os").environ.items() if k != "STOP_GUESSING_CHAIN_KEY"}
    env["STOP_GUESSING_KEYRING_DISABLED"] = "1"
    res = subprocess.run([*CLI, "demo", "--posture", "steer"],  # noqa: S603
                         capture_output=True, text=True, cwd=str(repo_root()), timeout=300, env=env)
    if res.returncode == 2:
        assert "REFUSED" in res.stdout
    else:
        # A keychain-backed key was discovered without the env var — that is the documented
        # provider chain working, not a failure. Assert it really did have one.
        assert "chain intact=True keyed=True" in res.stdout


# ── both are declared, and the claims say so ─────────────────────────────────


def test_the_claims_still_declare_these_surfaces():
    """Regression guard on the withdrawal itself: if these vanish again, this test fails."""
    from stop_guessing.prove import runner

    surfaces = {s for c in runner.load_claims()["claims"] for s in (c.get("surface") or [])}
    assert 'cli:"stop-guessing record emit"' in surfaces
    assert 'cli:"stop-guessing demo --posture steer"' in surfaces
