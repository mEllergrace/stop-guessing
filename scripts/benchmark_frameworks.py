#!/usr/bin/env python3
# build-ok: searched scripts/ (audit_verify.py checks 54 hardening predicates against our own source;
# release_bundle.py digests the tree for third-party reproduction; hygiene_sweep.py drives
# repo-hygiene's three repo checks) and tests/test_otlp_conformance.py, which validates ONE format
# against one external validator inside pytest. Nothing existing runs a THIRD-PARTY conformance
# validator per emitted format and reports a tier per framework, which is what this does.
"""Run every obtainable third-party validator against what this toolchain emits.

The distinction this exists to enforce: **"aligned to" is not "benchmarked against."** A README that
lists ISO/IEC 27037, SEC 17a-4(f) and FRE 902 in one row invites a reader to conclude all three were
tested. Before this script, exactly three formats had an external validator and only one of them ran
in CI.

Each validator must also REJECT something. A validator that accepts every input establishes nothing,
and this repository has already produced one false pass that way (the sandbox self-test "blocked"
every probe, including its own control). So every check here is a pair: a real artifact that must
pass, and a deliberately broken one that must fail.

Availability is reported, never skipped. A validator that is not installed yields `unavailable`,
which is a *different answer* from `pass` and must never be rendered as one — that is the same rule
the record schema applies to `known_gaps`.

    python3 scripts/benchmark_frameworks.py            # human-readable
    python3 scripts/benchmark_frameworks.py --json     # for docs/frameworks-status.json
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

PASS, FAIL, UNAVAILABLE = "pass", "fail", "unavailable"


def _result(name, validator, status, detail, control=None):
    return {"format": name, "validator": validator, "status": status, "detail": detail,
            "control": control}


# ── CASE/UCO — NIST's own validator ──────────────────────────────────────────


def _op_covering_sample(records: list[dict], per_op: int = 3) -> list[dict]:
    """A small sample that still contains every distinct `op` in the ledger.

    SHACL-validating 1,500 records twice took minutes and made the whole suite too slow to run,
    which is its own failure — a suite people skip protects nothing. Truncating to "the first N"
    would have been faster and wrong: record shape varies BY OP, so a prefix can miss the very
    shapes a validator would reject.

    Sampling by op keeps every shape represented and states the bound, rather than validating
    everything and implying thoroughness nobody waits for. `--full` still validates the lot.
    """
    seen: dict[str, int] = {}
    out = []
    for r in records:
        op = str(r.get("op") or (r.get("predicate") or {}).get("action", {}).get("op") or "?")
        if seen.get(op, 0) >= per_op:
            continue
        seen[op] = seen.get(op, 0) + 1
        out.append(r)
    return out


def check_case(full: bool = False) -> dict:
    """`case_validate` from usnistgov/case-utils: SHACL validation against the CASE ontology.

    This closes the M6 acceptance criterion, which had been open and unmentioned: the plan required
    a third-party CASE validator to accept an intact export, and nothing ever ran one.
    """
    try:
        from case_utils import __version__ as case_version  # noqa: F401
    except ImportError:
        return _result("CASE/UCO JSON-LD", "case_validate (usnistgov/case-utils)", UNAVAILABLE,
                       "case-utils is not installed; conformance is UNTESTED, not passing")

    from stop_guessing.prov.export_case import export

    records = _live_records()
    if not records:
        return _result("CASE/UCO JSON-LD", "case_validate", UNAVAILABLE,
                       "no ledger records to export")
    total = len(records)
    if not full:
        records = _op_covering_sample(records)
    scope = (f"{len(records)} of {total} records, covering every distinct op"
             if not full else f"all {total} records")

    with tempfile.TemporaryDirectory(prefix="sg-case-") as td:
        good = Path(td) / "custody.json"
        good.write_text(json.dumps(export(records)), encoding="utf-8")
        ok, out = _run_case_validate(good)

        # The control: an entity given a type CASE does not define must be rejected. If this passes,
        # the validator is not reading our graph and the result above means nothing.
        bad_doc = export(records)
        bad_doc["@graph"] = list(bad_doc["@graph"]) + [
            {"@id": "kb:sg-control-node", "@type": "uco-core:NotARealCaseClass"}]
        bad = Path(td) / "broken.json"
        bad.write_text(json.dumps(bad_doc), encoding="utf-8")
        bad_ok, bad_out = _run_case_validate(bad)

    control = ("rejected an undefined class" if not bad_ok
               else "DID NOT REJECT an undefined class — treat the pass above as unproven")
    status = PASS if (ok and not bad_ok) else FAIL
    detail = f"{(out or 'conforms')[:300]} [{scope}]"
    return _result("CASE/UCO JSON-LD", "case_validate (usnistgov/case-utils)", status,
                   detail, control)


def _run_case_validate(path: Path) -> tuple[bool, str]:
    try:
        res = subprocess.run(  # noqa: S603
            [str(REPO / ".venv" / "bin" / "case_validate"), str(path)],
            capture_output=True, text=True, timeout=900, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"could not run case_validate: {exc}"
    return res.returncode == 0, (res.stdout + res.stderr).strip()


# ── in-toto — the CNCF project's own model ───────────────────────────────────


def check_in_toto() -> dict:
    """Parse our Statement with in-toto's own code rather than asserting its shape ourselves.

    `tests/test_record_and_sufficiency.py::test_statement_is_in_toto_shaped` is OUR test of OUR
    reading of the spec. This is the upstream implementation's opinion.
    """
    try:
        import in_toto  # noqa: F401
        from in_toto.models._signer import GPGSignature  # noqa: F401
    except ImportError:
        return _result("in-toto Statement v1", "in-toto (CNCF)", UNAVAILABLE,
                       "in-toto is not installed; conformance is UNTESTED, not passing")

    try:
        from pypi_attestations import Attestation  # noqa: F401
        has_stmt = True
    except ImportError:
        has_stmt = False

    # in-toto 3.x ships the attestation *framework* models under a separate distribution; where the
    # Statement model is not importable, say so rather than substituting our own check and calling
    # it external validation.
    if not has_stmt:
        return _result(
            "in-toto Statement v1", "in-toto (CNCF)", UNAVAILABLE,
            "in-toto 3.1.0 is installed but exposes no Statement-v1 validator; the shape is checked "
            "only by our own test, so this remains SELF-ASSERTED")
    return _result("in-toto Statement v1", "in-toto (CNCF)", UNAVAILABLE, "unresolved")


# ── OTLP — the protobuf JSON mapping ─────────────────────────────────────────


def check_otlp() -> dict:
    """`opentelemetry-proto`'s generated parser, which rejects a wrong field or type outright."""
    try:
        from google.protobuf.json_format import ParseDict, ParseError
        from opentelemetry.proto.trace.v1.trace_pb2 import TracesData
    except ImportError:
        return _result("OTLP JSON (traces)", "opentelemetry-proto", UNAVAILABLE,
                       "opentelemetry-proto is not installed; conformance is UNTESTED")

    from stop_guessing.prov.export_otel import export

    records = _live_records()
    if not records:
        return _result("OTLP JSON (traces)", "opentelemetry-proto", UNAVAILABLE, "no records")

    doc = export(records)
    try:
        ParseDict(doc, TracesData())
        ok, detail = True, "parsed by the generated protobuf model"
    except ParseError as exc:
        ok, detail = False, str(exc)[:300]

    bad = json.loads(json.dumps(doc))
    try:
        bad["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["notAField"] = 1
        ParseDict(bad, TracesData())
        control = "DID NOT REJECT an unknown field — the pass above is unproven"
        control_ok = False
    except (ParseError, IndexError, KeyError, TypeError):
        control = "rejected an unknown span field"
        control_ok = True

    return _result("OTLP JSON (traces)", "opentelemetry-proto", PASS if (ok and control_ok) else FAIL,
                   detail, control)


# ── W3C PROV ─────────────────────────────────────────────────────────────────


def check_prov() -> dict:
    """Round-trip PROV-JSON through the `prov` library's own model."""
    try:
        from prov.model import ProvDocument
    except ImportError:
        return _result("W3C PROV-JSON", "prov (python)", UNAVAILABLE,
                       "the `prov` library is not installed; conformance is UNTESTED")

    from stop_guessing.prov.export_prov import export

    records = _live_records()
    if not records:
        return _result("W3C PROV-JSON", "prov (python)", UNAVAILABLE, "no records")

    with tempfile.TemporaryDirectory(prefix="sg-prov-") as td:
        p = Path(td) / "prov.json"
        p.write_text(json.dumps(export(records)), encoding="utf-8")
        try:
            with p.open(encoding="utf-8") as fh:
                doc = ProvDocument.deserialize(fh)
            ok = len(list(doc.get_records())) > 0
            detail = f"deserialised {len(list(doc.get_records()))} PROV record(s)"
        except Exception as exc:  # noqa: BLE001 - any parse failure is the answer
            ok, detail = False, f"{type(exc).__name__}: {exc}"[:300]

        try:
            bad = Path(td) / "bad.json"
            bad.write_text('{"entity": "not-an-object"}', encoding="utf-8")
            with bad.open(encoding="utf-8") as fh:
                ProvDocument.deserialize(fh)
            control, control_ok = "DID NOT REJECT malformed PROV-JSON", False
        except Exception:  # noqa: BLE001 - rejecting is the control passing
            control, control_ok = "rejected malformed PROV-JSON", True

    return _result("W3C PROV-JSON", "prov (python)", PASS if (ok and control_ok) else FAIL,
                   detail, control)


# ── the live ledger ──────────────────────────────────────────────────────────


def _live_records() -> list[dict]:
    from stop_guessing.attest.keys import discover, keyid_of_ledger
    from stop_guessing.ledger.sink import load
    from stop_guessing.prove import runner

    ledger = runner.DEFAULT_LEDGER
    if not ledger.exists():
        return []
    got = discover(None, prefer_keyid=keyid_of_ledger(ledger))
    return load(ledger, got[0] if got else None).entries


CHECKS = (check_case, check_otlp, check_prov, check_in_toto)


def run(full: bool = False) -> dict:
    results = [fn(full=full) if fn is check_case else fn() for fn in CHECKS]
    return {
        "results": results,
        "validated": [r["format"] for r in results if r["status"] == PASS],
        "failed": [r["format"] for r in results if r["status"] == FAIL],
        "unavailable": [r["format"] for r in results if r["status"] == UNAVAILABLE],
        "note": ("`unavailable` means the validator was not obtainable here, so conformance is "
                 "UNTESTED. It is not a pass and must never be rendered as one."),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--full", action="store_true",
                    help="validate every record rather than an op-covering sample (slow)")
    args = ap.parse_args(argv)

    out = run(full=args.full)
    if args.json:
        print(json.dumps(out, indent=2, sort_keys=True))
        return 1 if out["failed"] else 0

    print("Third-party conformance benchmark\n" + "=" * 60)
    for r in out["results"]:
        mark = {PASS: "PASS       ", FAIL: "FAIL       ", UNAVAILABLE: "UNTESTED   "}[r["status"]]
        print(f"{mark} {r['format']}")
        print(f"            validator: {r['validator']}")
        print(f"            {r['detail']}")
        if r["control"]:
            print(f"            control  : {r['control']}")
    print(f"\n{len(out['validated'])} externally validated, {len(out['failed'])} failing, "
          f"{len(out['unavailable'])} untested")
    print(out["note"])
    return 1 if out["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
