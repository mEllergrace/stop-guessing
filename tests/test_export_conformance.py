"""Every exporter, against the REAL ledger, checked by a third party's validator.

Three defects hid behind the absence of this file (#89, #90, #91):

  #89  all three exporters crashed on the real ledger. They were written against the gate's nested
       `CustodyRecord` predicate, where `actor` is an object; `prove` and the lifecycle hooks write
       flat events where `actor` is a string. 1,493 live records are flat, so `stop-guessing export
       prov|case|otel` exited 1 for every format. The only export test fed a pytest FIXTURE, so the
       primitive was validated while the path a user runs was broken — the external review's central
       finding, for the third time.
  #90  `cmd_ops._key()` omitted `prefer_keyid`, selected a key the ledger was not written under, and
       reported "chain broken at 0 … edited in place". The tool accused its own evidence of
       tampering. `claims check` and `export` disagreed about whether the same file was forged.
  #91  the CASE export failed NIST's `case_validate` — 4,488 SHACL violations from one root cause
       (untyped `xsd:dateTime`), then 121 Info advisories about UUID identifiers.

So these tests use the live ledger and third-party validators, never a hand-built record.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from stop_guessing.version import repo_root

REPO = repo_root()
sys.path.insert(0, str(REPO / "scripts"))


@pytest.fixture(scope="module")
def live_records():
    from stop_guessing.attest.keys import discover, keyid_of_ledger
    from stop_guessing.ledger.sink import load
    from stop_guessing.prove import runner

    ledger = runner.DEFAULT_LEDGER
    if not ledger.exists():
        pytest.skip("no ledger on this machine")
    got = discover(None, prefer_keyid=keyid_of_ledger(ledger))
    if not got:
        pytest.skip("no chain key")
    recs = load(ledger, got[0]).entries
    assert recs, "the ledger is empty"
    return recs


# ── #89: they must not crash on what the ledger actually holds ────────────────


@pytest.mark.parametrize("module", ["export_prov", "export_case", "export_otel"])
def test_every_exporter_runs_on_the_real_ledger(module, live_records):
    mod = __import__(f"stop_guessing.prov.{module}", fromlist=["export"])
    out = mod.export(live_records)
    assert out, f"{module} produced nothing"
    assert len(json.dumps(out)) > 1000, f"{module} produced a suspiciously small export"


def test_the_flat_record_shape_is_normalised_not_guessed():
    """A flat record has no operator and no delegation. Those keys must be ABSENT, not empty.

    Filling them would manufacture a custodian who never existed, which is worse than the crash: an
    export that invents a chain of custody is not a chain of custody.
    """
    from stop_guessing.prov.vocab import normalise

    flat = {"op": "proof.run", "actor": "stop-guessing/0.5.3", "at": "2026-08-05T10:00:00.000Z",
            "seq": 7, "known_gaps": [], "alterations": []}
    p = normalise(flat)
    assert p["actor"]["agent_id"] == "stop-guessing/0.5.3"
    assert p["actor"]["prov_type"] == "prov:SoftwareAgent"
    assert "operator" not in p["actor"], "an operator identity was invented for a flat record"
    assert "acted_on_behalf_of" not in p["actor"], "a delegation edge was invented"
    assert p["record"]["at"] == "2026-08-05T10:00:00.000Z"
    assert p["known_gaps"] == [] and p["alterations"] == [], (
        "Tier-A assertions must survive normalisation verbatim; dropping them would turn "
        "'nothing was altered' into 'nobody looked'")


def test_a_nested_predicate_record_is_passed_through_unchanged():
    """The control: normalisation must not rewrite the shape it was already correct for."""
    from stop_guessing.prov.vocab import normalise

    nested = {"predicate": {"actor": {"agent_id": "spiffe://x", "operator": {"identity": "me"}},
                            "record": {"id": "coc:1", "at": "2026-08-05T10:00:00.000Z"}}}
    p = normalise(nested)
    assert p["actor"]["operator"]["identity"] == "me"
    assert p["record"]["id"] == "coc:1"


# ── #90: the CLI must not accuse its own ledger of tampering ─────────────────


@pytest.mark.parametrize("fmt", ["prov", "case", "otel"])
def test_the_export_cli_succeeds_against_the_proof_ledger(fmt):
    res = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "stop_guessing.cli.main", "export", fmt,
         "--path", ".stop-guessing/proofs.jsonl"],
        capture_output=True, text=True, cwd=str(REPO), timeout=900, stdin=subprocess.DEVNULL)
    assert res.returncode == 0, f"export {fmt} failed: {(res.stdout + res.stderr)[-400:]}"
    assert "broken" not in res.stdout.lower(), "the CLI reported the chain broken"


def test_key_selection_prefers_the_key_the_ledger_was_written_under():
    """The root cause of #90, asserted directly rather than through a command's exit code."""
    from stop_guessing.attest.keys import keyid_of_ledger
    from stop_guessing.cli import cmd_ops
    from stop_guessing.prove import runner

    ledger = runner.DEFAULT_LEDGER
    if not ledger.exists():
        pytest.skip("no ledger")
    written_under = keyid_of_ledger(ledger)
    if not written_under:
        pytest.skip("ledger records no keyid")

    class Args:
        keyfile = None
        path = str(ledger)

    key = cmd_ops._key(Args())
    assert key is not None, "no key discovered at all"
    assert key.keyid == written_under, (
        f"cmd_ops chose {key.keyid} but the ledger was written under {written_under}; every entry "
        "will fail its MAC and the tool will report tampering that did not happen")


# ── #91: third-party validators, with their controls ────────────────────────


def test_case_export_conforms_to_nist_case_validate():
    """The plan's M6 acceptance criterion, which had never actually been run."""
    from benchmark_frameworks import check_case

    r = check_case()
    if r["status"] == "unavailable":
        pytest.skip(f"validator unavailable: {r['detail']}")
    assert r["status"] == "pass", f"case_validate: {r['detail']}"
    assert r["control"] and "DID NOT REJECT" not in r["control"], (
        f"the validator accepted a deliberately broken graph, so the pass is unproven: {r['control']}")


def test_case_identifiers_are_deterministic_and_uuid_shaped(live_records):
    """UUIDv5, so conformance did not cost reproducibility.

    A random UUID per export would conform and would make every export a different artifact —
    unusable for a toolchain that digests and pins its own outputs.
    """
    import re

    from stop_guessing.prov.export_case import export

    first = export(live_records[:20])
    second = export(live_records[:20])
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True), (
        "the CASE export is not byte-stable across runs; it cannot be digested or pinned")

    uuid_tail = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}$")
    ids = [n["@id"] for n in first["@graph"] if str(n.get("@id", "")).startswith("kb:")]
    assert ids, "no kb: identifiers were emitted"
    bad = [i for i in ids if not uuid_tail.search(i)]
    assert not bad, f"identifiers do not end in an RFC-4122 UUID: {bad[:3]}"


def test_the_readable_identifier_is_preserved(live_records):
    """Conforming must not make the graph opaque — the original id stays as sg:localId."""
    from stop_guessing.prov.export_case import export

    graph = export(live_records[:20])["@graph"]
    assert any(n.get("sg:localId") for n in graph), (
        "UUID identifiers replaced the readable ids with nothing to map them back to")


def test_prov_and_otlp_still_validate():
    from benchmark_frameworks import check_otlp, check_prov

    for r in (check_otlp(), check_prov()):
        if r["status"] == "unavailable":
            continue
        assert r["status"] == "pass", f"{r['format']}: {r['detail']}"
        assert "DID NOT REJECT" not in (r["control"] or ""), r["control"]


def test_untested_is_never_reported_as_passing():
    """`unavailable` and `pass` are different answers and must not collapse.

    Same rule the record schema applies to `known_gaps`: absence of a check is not a clean result.
    """
    from benchmark_frameworks import run

    out = run()
    assert set(out["validated"]).isdisjoint(out["unavailable"])
    assert "not a pass" in out["note"]
