"""Recording is not monitoring — something has to decide what wakes a human.

Ported from `classifyAlert`/`alertsFrom` in rockin-robin, including the rule that matters most:
**an unrecognised event kind alerts rather than being dropped.** A monitor that silently ignores
what it does not recognise is worse than no monitor, because it carries a false assurance.

Deliberately quiet on routine traffic. The failure mode of a monitoring system is not missing an
event — it is alerting so often that people stop reading.
"""

from __future__ import annotations

from dataclasses import dataclass

from stop_guessing.ledger.chain import ChainKey, verify

#: Ops that wake a human immediately — the record of what happened cannot be trusted.
WAKE_HUMAN = {
    "reconciliation-failed": "evidence reconciliation failed — the record of what ran cannot be trusted",
    "recorder.selfcheck": "the recorder failed its own integrity check",
    "custody.declassify": "a classification was dropped — a human authorised removing a label",
}

#: Ops that wake an operator — something was attempted that policy does not permit.
WAKE_OPERATOR = {
    "authorization-refused": "an action was attempted that policy does not permit",
    "artifact.egress": "tainted data left, or attempted to leave, the boundary",
    "custody.alteration": "a record was altered, with justification — confirm the justification",
}

#: Ops that are routine by construction. Anything not listed here or above escalates.
ROUTINE = {
    "session.open", "session.close", "prompt.submit", "tool.request", "tool.decision",
    "tool.result", "artifact.identify", "artifact.classify", "artifact.read", "artifact.write",
    "artifact.derive", "delegation.scaffold", "delegation.run", "agent.spawn", "agent.merge",
    "custody.checkpoint", "custody.handover", "ledger.seal", "ledger.certify", "caiq.inspect",
    "caiq.attest", "policy.load", "dispatch", "turn-complete", "intervention", "provision",
    "teardown",
}


@dataclass(frozen=True)
class AlertDecision:
    alert: bool
    reason: str
    wake: str | None = None


def classify(entry: dict) -> AlertDecision:
    """Should this record wake somebody?"""
    op = entry.get("op") or entry.get("kind")
    severity = entry.get("severity", "info")

    if op in WAKE_HUMAN:
        return AlertDecision(True, WAKE_HUMAN[op], "human")
    if op in WAKE_OPERATOR:
        return AlertDecision(True, WAKE_OPERATOR[op], "operator")
    if severity == "critical":
        return AlertDecision(True, f"record marked critical: {entry.get('detail', '')}", "human")
    if op in ROUTINE:
        return AlertDecision(False, "routine activity")
    return AlertDecision(
        True,
        f"unrecognised op {op!r} — refusing to ignore what is not understood",
        "operator",
    )


@dataclass(frozen=True)
class Alert:
    entry: dict | None
    reason: str
    wake: str | None


def alerts_from(log: list[dict], key: ChainKey | None = None) -> list[Alert]:
    """Everything a human should see, chain first.

    A monitoring surface that reports on a record it has not checked is reporting on fiction, so
    the chain is verified before any record in it is believed.
    """
    out: list[Alert] = []
    verdict = verify(log, key)
    if not verdict.intact:
        at = verdict.broken_at or 0
        out.append(
            Alert(
                log[at] if at < len(log) else None,
                f"LEDGER CHAIN BROKEN at entry {at}: {verdict.reason} — tampering or corruption",
                "human",
            )
        )
    elif log and not verdict.verified_keyed:
        out.append(
            Alert(
                None,
                "chain shape is intact but could not be verified against its key — "
                "report this as 'chain-only', never as tamper-proof",
                "operator",
            )
        )
    for e in log:
        d = classify(e)
        if d.alert:
            out.append(Alert(e, d.reason, d.wake))
    return out
