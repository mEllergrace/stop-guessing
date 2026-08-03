"""An audit trail owned by the audited party is not an audit trail.

Ported from `reconcileExecution`/`issueNonce` in `rockin-robin/src/rockinRobinWorkflow.ts`. The
orchestrator's own dispatch ledger — which the agent never writes — is the source of truth; what
the agent *reports* is corroboration. Every disagreement is a finding in its own right: a
fabricated pass, a replayed one, a wrong or missing nonce, a dispatch nobody reported, or one
actor claiming another's work.

This is the direct answer to the Berkeley RDI result (April 2026), where a zero-capability agent
scored ~100% on eight benchmarks by installing a fake `curl` that returned fabricated success to
the grader. Self-reported success is not evidence.

**Nonce upgrade over the original.** rockin-robin derives the nonce with FNV-1a and says plainly
that it is not a security primitive — deterministic, unauthenticated, re-derivable by anyone who
knows the inputs. Its own docstring notes that swapping in a secret-held value is "a drop-in
change to this function alone", so that is what this does: an HMAC under the chain key when one
exists, falling back to the original derivation when it does not, with the mode recorded.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from stop_guessing.ledger.chain import ChainKey

NONCE_HEX = 16


def _fnv_nonce(instance_id: str, seq: int) -> str:
    """The original FNV-1a derivation, kept so an unkeyed ledger still gets a distinct nonce."""
    h1 = 0x811C9DC5
    h2 = 0x01000193
    s = f"{instance_id}#{seq}#sg-nonce"
    for i, ch in enumerate(s):
        h1 = ((h1 ^ ord(ch)) * 0x01000193) & 0xFFFFFFFF
        h2 = ((h2 + ord(ch) * (i + 7)) * 0x85EBCA6B) & 0xFFFFFFFF
    return (f"{h1:08x}{h2:08x}").ljust(NONCE_HEX, "0")


def issue_nonce(instance_id: str, seq: int, key: ChainKey | None = None) -> str:
    """A per-dispatch nonce, distinct for every (actor, sequence).

    Keyed: unforgeable by the recorded party, so a rewritten history cannot produce the value
    that was issued for a pass it never received. Unkeyed: still distinct and still makes a
    rewrite awkward, but derivable — report it as such rather than claiming more.
    """
    if key is None:
        return _fnv_nonce(instance_id, seq)
    material = f"{instance_id}#{seq}#sg-nonce".encode()
    return hmac.new(key.material, material, hashlib.sha256).hexdigest()[:NONCE_HEX]


def nonce_mode(key: ChainKey | None) -> str:
    return "hmac-sha256" if key is not None else "fnv1a-derived"


@dataclass(frozen=True)
class Dispatch:
    """What the recorder sent. The agent never writes this."""

    seq: int
    actor: str
    action: str
    nonce: str


@dataclass(frozen=True)
class Reported:
    """What the agent claims happened. Corroboration, not evidence."""

    seq: int
    actor: str
    action: str
    nonce: str | None = None


@dataclass(frozen=True)
class Reconciliation:
    verified: bool
    findings: list[str]

    def to_dict(self) -> dict:
        return {"verified": self.verified, "findings": list(self.findings)}


def reconcile(ledger: list[Dispatch], reported: list[Reported]) -> Reconciliation:
    """Compare the recorder's dispatch ledger against what was claimed."""
    findings: list[str] = []
    by_seq = {d.seq: d for d in ledger}
    seen: set[int] = set()

    for r in reported:
        d = by_seq.get(r.seq)
        if d is None:
            findings.append(
                f"report at seq {r.seq} ({r.actor}/{r.action}) was never dispatched — "
                "fabricated or replayed"
            )
            continue
        if r.seq in seen:
            findings.append(f"seq {r.seq} reported more than once — replayed")
        seen.add(r.seq)
        if r.actor != d.actor:
            findings.append(
                f"seq {r.seq}: dispatched to {d.actor} but {r.actor} claims it — "
                "attribution mismatch"
            )
        if r.action != d.action:
            findings.append(
                f"seq {r.seq}: dispatched {d.action} but {r.actor} reports {r.action}"
            )
        if r.nonce is None:
            findings.append(f"seq {r.seq}: no nonce returned — the dispatch cannot be bound")
        elif not hmac.compare_digest(r.nonce, d.nonce):
            findings.append(
                f"seq {r.seq}: nonce mismatch — expected the value issued at dispatch, "
                f"got {r.nonce!r}"
            )

    for d in ledger:
        if d.seq not in seen:
            findings.append(
                f"seq {d.seq} ({d.actor}/{d.action}) was dispatched but no report "
                "corroborates it — unreported execution"
            )

    return Reconciliation(not findings, findings)
