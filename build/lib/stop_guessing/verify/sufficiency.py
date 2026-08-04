"""Does this ledger actually answer the question an auditor is asking?

DEMM-Bench (arXiv:2606.20634) evaluated agent-runtime evidence across eight regimes and found
that **trace-present and schema-present baselines overclaim sufficiency on 75% of cases, and
ledger-present on 50%**. Its opening line is the problem statement for this module:

    "Agent-runtime systems emit traces, ledgers, provenance graphs, policy logs, delegation
    tokens, cache events, and tool-firewall records, but those containers do not necessarily
    answer governance questions about a specific decision."

So the answer to "is this sufficient?" is never "yes, there is a ledger". It is per-question, per
regime, and it defaults to `incomplete`. Reporting `incomplete` when a regime is unpopulated is
the entire point — a gate that says `sufficient` because records exist is the overclaim.
"""

from __future__ import annotations

from dataclasses import dataclass

from stop_guessing.ledger.entry import dig

#: The eight regimes, each with the predicate paths that would populate it.
REGIMES: dict[str, tuple[str, ...]] = {
    "actor": ("actor.agent_id", "actor.operator", "actor.runtime_action_id"),
    "authority": ("authority.posture", "authority.capability"),
    "action": ("action.op", "action.method.kind", "action.input_digest"),
    "policy": ("policy.policy_set_digest", "policy.determining_policy"),
    "decision_basis": ("decision.outcome", "decision.basis"),
    "resource_touch": ("resources.used",),
    "lifecycle": ("lifecycle.session_id", "lifecycle.prompt_id"),
    "verification": ("verification.chain", "verification.strength", "verification.known_gaps"),
}

#: Governance questions, and the regimes each genuinely needs. Answering "who touched this data"
#: with an actor field alone is exactly the overclaim DEMM-Bench measured.
QUESTIONS: dict[str, tuple[str, ...]] = {
    "who acted, on whose authority": ("actor", "authority", "lifecycle"),
    "what data was touched, and where did it go": ("action", "resource_touch", "verification"),
    "why was this permitted or refused": ("policy", "decision_basis", "authority"),
    "can this record be trusted": ("verification", "actor", "lifecycle"),
}


#: Paths where an EMPTY value is a positive assertion, not an absence. Same rule as the record
#: schema: ``known_gaps: []`` asserts "nothing was skipped" and must count as populated. Treating
#: it as a gap would contradict the very distinction the schema exists to preserve — and was a
#: real bug, caught by CLAIM-06's own proof procedure failing.
ASSERTION_PATHS = frozenset({"verification.known_gaps", "alterations"})


@dataclass(frozen=True)
class RegimeResult:
    regime: str
    populated: int
    total: int
    missing: list[str]

    @property
    def complete(self) -> bool:
        return not self.missing


def assess_record(predicate: dict) -> dict[str, RegimeResult]:
    out: dict[str, RegimeResult] = {}
    for regime, paths in REGIMES.items():
        missing = []
        for path in paths:
            present, value = dig(predicate, path)
            if not present:
                missing.append(path)
            elif path in ASSERTION_PATHS:
                continue          # present is enough; [] is the assertion
            elif value in (None, "", [], {}):
                missing.append(path)
        out[regime] = RegimeResult(regime, len(paths) - len(missing), len(paths), missing)
    return out


def assess(records: list[dict]) -> dict:
    """Assess a ledger. Every question defaults to `incomplete`, and stays there until earned."""
    # A record may be a bare predicate, a full in-toto Statement, or a ledger entry carrying a
    # Statement under "statement". Accept all three rather than silently assessing the wrapper and
    # reporting every regime as missing.
    predicates = []
    for r in records:
        if "statement" in r and isinstance(r["statement"], dict):
            predicates.append(r["statement"].get("predicate", r["statement"]))
        else:
            predicates.append(r.get("predicate", r))
    if not predicates:
        return {
            "records": 0,
            "verdict": "incomplete",
            "regimes": {},
            "questions": {q: {"answerable": False, "blocked_by": list(rs)}
                          for q, rs in QUESTIONS.items()},
            "note": "no records — an empty ledger answers nothing",
        }

    per_regime: dict[str, dict] = {}
    for regime in REGIMES:
        complete = 0
        missing_paths: dict[str, int] = {}
        for p in predicates:
            res = assess_record(p)[regime]
            if res.complete:
                complete += 1
            for m in res.missing:
                missing_paths[m] = missing_paths.get(m, 0) + 1
        per_regime[regime] = {
            "complete_records": complete,
            "total_records": len(predicates),
            "fully_populated": complete == len(predicates),
            "missing": dict(sorted(missing_paths.items(), key=lambda kv: -kv[1])),
        }

    questions = {}
    for q, needed in QUESTIONS.items():
        blocked = [r for r in needed if not per_regime[r]["fully_populated"]]
        questions[q] = {"answerable": not blocked, "blocked_by": blocked}

    answerable = sum(1 for v in questions.values() if v["answerable"])
    verdict = "sufficient" if answerable == len(questions) else "incomplete"
    return {
        "records": len(predicates),
        "verdict": verdict,
        "answerable": answerable,
        "questions_total": len(questions),
        "regimes": per_regime,
        "questions": questions,
    }


def format_report(result: dict) -> str:
    lines = [f"records assessed : {result['records']}",
             f"verdict          : {result['verdict'].upper()}"]
    if result["records"]:
        lines.append(f"questions        : {result['answerable']}/{result['questions_total']} "
                     "answerable")
        lines.append("")
        lines.append("regime            populated")
        for name, r in result["regimes"].items():
            mark = "ok " if r["fully_populated"] else "GAP"
            lines.append(f"  {mark} {name:<16} {r['complete_records']}/{r['total_records']}")
            for path, count in list(r["missing"].items())[:3]:
                lines.append(f"        missing {path} in {count} record(s)")
        lines.append("")
        for q, v in result["questions"].items():
            if v["answerable"]:
                lines.append(f"  ANSWERABLE   {q}")
            else:
                lines.append(f"  INCOMPLETE   {q}")
                lines.append(f"               blocked by: {', '.join(v['blocked_by'])}")
    if result["verdict"] != "sufficient":
        lines.append("")
        lines.append("Reporting INCOMPLETE rather than claiming sufficiency it cannot back.")
    return "\n".join(lines)
