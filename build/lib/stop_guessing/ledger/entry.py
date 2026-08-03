"""The custody record, and the three tiers of requiredness.

Structure follows IMPLEMENTATION_PLAN.md §7: an in-toto Statement envelope whose predicate is
organised by the **eight evidence regimes** from DEMM-Bench (arXiv:2606.20634), which found
ledger-present baselines overclaim evidence sufficiency on 50% of governance questions. The
regimes are the completeness checklist that answers that finding.

The distinction the whole schema turns on:

    "alterations": []     -> a positive assertion that nothing was altered
    (key absent)          -> nobody looked

The second is rejected at write. Absence of a field must never be readable as absence of the
thing — that is how a ledger comes to overclaim without anyone lying.

Three tiers, by consequence:

- **Tier A — refuse to write.** The recorder rejects the record entirely. In `steer`/`bar` the
  hook then fails closed; in `observe` it fails open and raises a critical alert.
- **Tier B — refuse to certify.** The record writes; the segment cannot be sealed or certified.
- **Tier C — degrades strength.** Valid record, lower `verification.strength`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

PREDICATE_TYPE = "https://stop-guessing.dev/Custody/v1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
RECORD_VERSION = "1.0.0"

#: Rejected at write. Dotted paths into the predicate.
TIER_A = (
    "record.id", "record.at", "record.recorded_at",
    "actor.agent_id", "actor.runtime_action_id", "actor.operator",
    "action.op", "action.method.kind", "action.input_digest",
    "authority.posture",
    "policy.policy_set_digest", "policy.determining_policy",
    "decision.outcome", "decision.channel",
    "lifecycle.session_id",
    "verification.chain", "verification.strength", "verification.known_gaps",
    "alterations",
)

#: Present-but-empty is meaningful; these must exist as keys even when empty.
TIER_A_ASSERTIONS = ("alterations", "verification.known_gaps")

#: Blocks sealing and certification, not writing.
TIER_B = (
    "actor.acted_on_behalf_of.prompt_id",
    "decision.basis",
    "authority.capability",
)

#: Lowers the reported strength.
TIER_C = ("verification.signature", "verification.timestamp.tsa", "verification.recorder")

OPS = frozenset({
    "session.open", "session.close", "prompt.submit", "tool.request", "tool.decision",
    "tool.result", "artifact.identify", "artifact.classify", "artifact.read", "artifact.write",
    "artifact.derive", "artifact.egress", "delegation.scaffold", "delegation.run", "agent.spawn",
    "agent.merge", "custody.handover", "custody.checkpoint", "custody.declassify",
    "custody.alteration", "ledger.seal", "ledger.certify", "caiq.inspect", "caiq.attest",
    "policy.load", "recorder.selfcheck", "proof.run",
})

OUTCOMES = frozenset({"allow", "ask", "deny", "defer", "allow-with-conditions"})
POSTURES = frozenset({"observe", "steer", "bar"})
METHOD_KINDS = frozenset({"direct-model", "delegated-script", "signed-script", "denied"})

STRENGTH_LADDER = (
    "chain-only", "chain-keyed", "chain-keyed+isolated", "+signed", "+tsa", "+transparency",
)


class RecordInvalid(Exception):
    """A record that cannot be written. Carries every missing path, not just the first."""

    def __init__(self, missing: list[str], detail: str = ""):
        self.missing = missing
        super().__init__(
            f"record rejected — {len(missing)} Tier-A field(s) missing or invalid: "
            f"{', '.join(missing)}{('. ' + detail) if detail else ''}"
        )


def dig(obj: Any, path: str) -> tuple[bool, Any]:
    """Walk a dotted path. Returns ``(present, value)`` so a present-but-None is distinguishable."""
    cur = obj
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return False, None
        cur = cur[part]
    return True, cur


def validate_tier_a(predicate: dict) -> list[str]:
    """Every Tier-A problem, in path order. Empty list means writable."""
    missing: list[str] = []
    for path in TIER_A:
        present, value = dig(predicate, path)
        if not present:
            missing.append(f"{path} (absent)")
        elif path in TIER_A_ASSERTIONS:
            if not isinstance(value, list):
                missing.append(f"{path} (must be a list; [] asserts 'nothing', absent means "
                               "'nobody looked')")
        elif value is None or value == "":
            missing.append(f"{path} (empty)")

    op = dig(predicate, "action.op")[1]
    if op is not None and op not in OPS:
        missing.append(f"action.op ({op!r} is not in the controlled vocabulary)")
    outcome = dig(predicate, "decision.outcome")[1]
    if outcome is not None and outcome not in OUTCOMES:
        missing.append(f"decision.outcome ({outcome!r} not in {sorted(OUTCOMES)})")
    posture = dig(predicate, "authority.posture")[1]
    if posture is not None and posture not in POSTURES:
        missing.append(f"authority.posture ({posture!r} not in {sorted(POSTURES)})")
    kind = dig(predicate, "action.method.kind")[1]
    if kind is not None and kind not in METHOD_KINDS:
        missing.append(f"action.method.kind ({kind!r} not in {sorted(METHOD_KINDS)})")
    return missing


def validate_tier_b(predicate: dict) -> list[str]:
    """What blocks sealing and certification. Posture-sensitive."""
    findings: list[str] = []
    posture = dig(predicate, "authority.posture")[1]
    for path in TIER_B:
        present, value = dig(predicate, path)
        if path == "actor.acted_on_behalf_of.prompt_id" and posture == "observe":
            continue
        if not present or value in (None, ""):
            findings.append(path)

    depth = dig(predicate, "actor.acted_on_behalf_of.delegation_depth")[1] or 0
    if depth and not dig(predicate, "actor.acted_on_behalf_of.delegation_chain")[1]:
        findings.append("actor.acted_on_behalf_of.delegation_chain (delegation_depth > 0)")

    op = dig(predicate, "action.op")[1]
    data_touching = {"artifact.read", "artifact.write", "artifact.derive", "artifact.egress"}
    if op in data_touching and not dig(predicate, "resources.used")[1]:
        findings.append("resources.used (data-touching op)")

    if dig(predicate, "action.method.kind")[1] == "delegated-script":
        passed = dig(predicate, "action.method.script.test_result.passed")[1]
        if passed is not True:
            findings.append("action.method.script.test_result.passed (must be true)")
    return findings


def strength(predicate: dict) -> str:
    """Where this record sits on the ladder. Reports the floor, never the ceiling."""
    chain = dig(predicate, "verification.chain")[1] or {}
    level = "chain-keyed" if chain.get("algo") == "hmac-sha256" else "chain-only"
    recorder = dig(predicate, "verification.recorder")[1] or {}
    if level == "chain-keyed" and (recorder.get("isolation_tier") or 0) >= 1:
        level = "chain-keyed+isolated"
    if (dig(predicate, "verification.signature")[1] or {}).get("present"):
        level = "+signed"
    if (dig(predicate, "verification.timestamp")[1] or {}).get("tsa"):
        level = "+tsa"
    return level


@dataclass
class CustodyRecord:
    """Builder. Produces the predicate; the chain assigns seq/prev_hash/hash on append."""

    op: str
    agent_id: str
    runtime_action_id: str
    operator: dict
    session_id: str
    posture: str
    outcome: str
    channel: str
    at: str
    recorded_at: str
    record_id: str
    method_kind: str = "direct-model"
    input_digest: str = ""
    policy_set_digest: str = ""
    determining_policy: str = ""
    alterations: list = field(default_factory=list)
    known_gaps: list = field(default_factory=list)
    chain: dict = field(default_factory=lambda: {"algo": "hmac-sha256"})
    extra: dict = field(default_factory=dict)

    def predicate(self) -> dict:
        p: dict[str, Any] = {
            "record_version": RECORD_VERSION,
            "record": {"id": self.record_id, "at": self.at, "recorded_at": self.recorded_at},
            "actor": {
                "prov_type": "prov:SoftwareAgent",
                "agent_id": self.agent_id,
                "runtime_action_id": self.runtime_action_id,
                "operator": self.operator,
            },
            "authority": {"posture": self.posture},
            "action": {
                "prov_type": "prov:Activity",
                "op": self.op,
                "method": {"kind": self.method_kind},
                "input_digest": self.input_digest,
            },
            "policy": {
                "policy_set_digest": self.policy_set_digest,
                "determining_policy": self.determining_policy,
            },
            "decision": {"outcome": self.outcome, "channel": self.channel},
            "lifecycle": {"session_id": self.session_id},
            "verification": {
                "chain": self.chain,
                "known_gaps": list(self.known_gaps),
                "strength": "chain-only",
            },
            "alterations": list(self.alterations),
        }
        _deep_merge(p, self.extra)
        p["verification"]["strength"] = strength(p)
        return p

    def build(self, *, subjects: list[dict] | None = None) -> dict:
        """The full in-toto Statement. Raises RecordInvalid rather than writing a partial record."""
        pred = self.predicate()
        missing = validate_tier_a(pred)
        if missing:
            raise RecordInvalid(missing)
        return {
            "_type": STATEMENT_TYPE,
            "subject": subjects or [],
            "predicateType": PREDICATE_TYPE,
            "predicate": pred,
        }


def _deep_merge(base: dict, overlay: dict) -> None:
    for k, v in overlay.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v
