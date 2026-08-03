"""Run proof procedures, record them in our own ledger, and write the record ids back.

This is the only writer of `proofs:` in `docs/claims.yaml`. The direction of causation is the
whole point: the evidence is produced first, in a ledger the agent cannot forge, and the artifact
is derived from it. Reversing that — filling the artifact and then hunting for evidence — is the
failure this toolchain exists to make impossible.

A proof reference is only honoured if its ledger record still verifies under the chain key. A
record id in `claims.yaml` whose chain has since broken is not a proof; `claims check` reports it
as broken rather than counting it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from stop_guessing.ledger.chain import ChainKey
from stop_guessing.ledger.sink import load, record
from stop_guessing.prove.registry import Procedure, ProofResult, all_procedures, get
from stop_guessing.version import __version__, repo_root

CLAIMS = repo_root() / "docs" / "claims.yaml"
DEFAULT_LEDGER = repo_root() / ".stop-guessing" / "proofs.jsonl"

PROOF_REF_PREFIX = "sg"


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def proof_ref(entry: dict) -> str:
    """A stable, checkable reference to one ledger record: ``sg:<seq>:<hash16>``."""
    return f"{PROOF_REF_PREFIX}:{entry['seq']}:{entry['hash'][:16]}"


def load_claims() -> dict:
    import yaml

    return yaml.safe_load(CLAIMS.read_text(encoding="utf-8"))


def save_claims(doc: dict) -> None:
    import yaml

    header = (
        "# STOP-GUESSING — application claims\n"
        "#\n"
        "# `proofs:` is written ONLY by `stop-guessing prove`. Never edit it by hand: a record id\n"
        "# a human could type proves only that a human typed. Each proof is a record id in this\n"
        "# toolchain's own keyed ledger, and `stop-guessing claims check` re-verifies the chain\n"
        "# covering it before counting it.\n"
        "#\n"
        "# See IMPLEMENTATION_PLAN.md §2.1 (definition of done) and §14 M10.\n\n"
    )
    body = yaml.safe_dump(doc, sort_keys=False, width=100, allow_unicode=True)
    CLAIMS.write_text(header + body, encoding="utf-8")


@dataclass
class RunOutcome:
    claim_id: str
    passed: bool
    ref: str | None
    observations: list[str]
    detail: str


def run_one(
    claim_id: str,
    key: ChainKey | None,
    ledger: Path = DEFAULT_LEDGER,
    *,
    write_back: bool = True,
) -> RunOutcome:
    """Execute one claim's procedure and record what it observed."""
    proc: Procedure | None = get(claim_id)
    if proc is None:
        return RunOutcome(claim_id, False, None, [], "no procedure registered")

    try:
        result: ProofResult = proc.fn()
    except Exception as exc:  # noqa: BLE001 - a crashing procedure is a finding, not a stack trace
        result = ProofResult(passed=False, observations=[f"procedure raised: {exc!r}"])

    entry = record(
        ledger,
        {
            "op": "proof.run",
            "actor": f"stop-guessing/{__version__}",
            "at": _now(),
            "severity": "info" if result.passed else "critical",
            "claim": claim_id,
            "proof_kind": proc.kind,
            "procedure": proc.fn.__name__,
            "procedure_digest": proc.source_digest(),
            "summary": proc.summary,
            "passed": result.passed,
            "observations": result.observations,
            "evidence": result.evidence,
            "detail": result.detail,
        },
        key,
    )
    ref = proof_ref(entry)

    if write_back and result.passed:
        doc = load_claims()
        for c in doc["claims"]:
            if c["id"] == claim_id:
                refs = list(c.get("proofs") or [])
                if ref not in refs:
                    refs.append(ref)
                c["proofs"] = refs
                c["last_proved"] = entry["at"]
                break
        save_claims(doc)

    return RunOutcome(claim_id, result.passed, ref, result.observations, result.detail)


def run_all(key: ChainKey | None, ledger: Path = DEFAULT_LEDGER,
            *, only: list[str] | None = None) -> list[RunOutcome]:
    procs = all_procedures()
    ids = only or sorted(procs)
    return [run_one(cid, key, ledger) for cid in ids if cid in procs]


def check(key: ChainKey | None, ledger: Path = DEFAULT_LEDGER) -> dict:
    """The release gate. A claim with no surviving proof is FAILED, not unassessed."""
    doc = load_claims()
    procs = all_procedures()
    loaded = load(ledger, key)
    by_ref = {proof_ref(e): e for e in loaded.entries if e.get("op") == "proof.run"}
    chain_ok = loaded.chain.intact

    rows = []
    for c in doc["claims"]:
        refs = list(c.get("proofs") or [])
        live, dead = [], []
        for ref in refs:
            e = by_ref.get(ref)
            if e is None:
                dead.append(f"{ref} not found in the ledger")
            elif not e.get("passed"):
                dead.append(f"{ref} records a FAILED run")
            elif e.get("claim") != c["id"]:
                dead.append(f"{ref} was recorded against {e.get('claim')}")
            else:
                proc = procs.get(c["id"])
                if proc and e.get("procedure_digest") not in (proc.source_digest(), "unavailable"):
                    dead.append(f"{ref} was produced by a since-modified procedure")
                else:
                    live.append(ref)
        proc = procs.get(c["id"])
        kind_ok = proc is None or proc.kind == c.get("proof_kind")
        rows.append({
            "id": c["id"],
            "milestone": c.get("milestone"),
            "proof_kind": c.get("proof_kind"),
            "has_procedure": c["id"] in procs,
            "kind_matches": kind_ok,
            "live": live,
            "dead": dead,
            "proven": bool(live) and chain_ok and kind_ok,
        })

    proven = [r for r in rows if r["proven"]]
    return {
        "chain_intact": chain_ok,
        "chain_reason": loaded.chain.reason,
        "chain_keyed": loaded.chain.verified_keyed,
        "ledger": str(ledger),
        "total": len(rows),
        "proven": len(proven),
        "unproven": [r["id"] for r in rows if not r["proven"]],
        "rows": rows,
        "ok": len(proven) == len(rows) and chain_ok,
    }


def attest_self(
    key: ChainKey | None,
    ledger: Path = DEFAULT_LEDGER,
    caiq_dir: Path | None = None,
) -> dict:
    """The one-line answer to the goal: claims -> proofs -> controls, plus the AI-CAIQ state.

    ``caiq_dir`` is injectable so this is testable hermetically. It was not, and a test asserting
    "the goal is not met before the workbook exists" started passing for the wrong reason the
    moment the real workbook was generated — a test reading production state is not a test.
    """
    result = check(key, ledger)
    doc = load_claims()

    controls: dict[str, list[str]] = {}
    for c in doc["claims"]:
        row = next(r for r in result["rows"] if r["id"] == c["id"])
        if row["proven"]:
            for ctrl in c.get("aicm") or []:
                controls.setdefault(ctrl, []).append(c["id"])

    cdir = caiq_dir or (repo_root() / "docs" / "ai-caiq")
    filled = sorted(p.name for p in cdir.glob("AI-CAIQ-*.xlsx")) if cdir.is_dir() else []
    answers = cdir / "stop-guessing.yaml"

    result["aicm_controls_evidenced"] = dict(sorted(controls.items()))
    result["caiq"] = {
        "answers_present": answers.is_file(),
        "filled_workbooks": filled,
        "filled_from_proofs": bool(filled) and answers.is_file(),
    }
    result["goal_met"] = bool(
        result["ok"] and result["chain_keyed"] and result["caiq"]["filled_from_proofs"]
    )
    return result


def summarise(result: dict) -> str:
    lines = [json.dumps({"proven": result["proven"], "total": result["total"]})]
    return "\n".join(lines)
