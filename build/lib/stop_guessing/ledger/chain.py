"""The tamper-evident chain.

Ported from `rockin-robin/src/rockinRobinAudit.ts`, which was already mapped to AICM LOG-03
(security monitoring and alerting) and LOG-10 (audit records protection). Two deliberate changes,
both because the threat model here is different:

**1. The chain is keyed.** rockin-robin chains with a bare SHA-256. That detects an *edit* — but
it does not detect a **rewrite**. An agent that can write to the ledger can truncate it at any
point and recompute every hash from there forward, producing a chain that verifies perfectly.
`verifyChain` would return ``intact: true`` over a fabricated history. Since the agent being
recorded is exactly the party with filesystem access, that is not a theoretical gap. Chaining with
HMAC-SHA256 under a key the agent cannot read makes a forged chain unproducible rather than merely
detectable. An unkeyed chain is still supported and still useful — it is honestly reported as
``chain-only`` strength rather than being passed off as tamper-proof.

**2. Every field participates, structurally.** rockin-robin joins a fixed list of seven named
fields. That is correct for a fixed schema and becomes a liability when the schema grows: a field
added later and forgotten here is a place to edit undetectably. Here the material is the canonical
JSON of the whole entry minus its own hash, so new fields are covered the moment they exist.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any

GENESIS = "0" * 64
"""Genesis link, so entry 0 is itself covered by the chain rather than dangling."""

ALGO_KEYED = "hmac-sha256"
ALGO_UNKEYED = "sha256"


@dataclass(frozen=True)
class ChainKey:
    """A chain key and the id recorded alongside it.

    The key material never enters a record; only ``keyid`` does. A ledger therefore says which
    key would verify it without disclosing anything that would let a reader forge it.
    """

    keyid: str
    material: bytes

    def __repr__(self) -> str:  # pragma: no cover - defensive, not logic
        return f"ChainKey(keyid={self.keyid!r}, material=<{len(self.material)} bytes>)"


@dataclass(frozen=True)
class ChainVerdict:
    """Whether a chain holds, and if not, exactly where it stops holding.

    ``broken_at`` matters more than ``intact``: "something was tampered with" is not actionable,
    "entry 57 was edited in place" is.
    """

    intact: bool
    broken_at: int | None = None
    reason: str | None = None
    verified_keyed: bool = False
    checked: int = 0

    def to_dict(self) -> dict:
        return {
            "intact": self.intact,
            "broken_at": self.broken_at,
            "reason": self.reason,
            "verified_keyed": self.verified_keyed,
            "checked": self.checked,
        }


def canonical_material(entry: dict[str, Any]) -> bytes:
    """Canonical bytes for an entry, excluding its own ``hash``.

    Sorted keys and tight separators so the same logical entry always produces the same bytes
    regardless of how it was constructed or round-tripped through JSON.
    """
    body = {k: v for k, v in entry.items() if k != "hash"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def hash_entry(entry: dict[str, Any], key: ChainKey | None) -> str:
    """The chain hash for one entry — HMAC-SHA256 when keyed, SHA-256 when not."""
    material = canonical_material(entry)
    if key is None:
        return hashlib.sha256(material).hexdigest()
    return hmac.new(key.material, material, hashlib.sha256).hexdigest()


def append(log: list[dict], event: dict, key: ChainKey | None = None) -> list[dict]:
    """Chain one event onto the log's head. Pure: returns a new list.

    ``seq``, ``prev_hash``, ``hash_alg``, ``keyid`` and ``hash`` are assigned here and may not be
    supplied by the caller — a record that could choose its own sequence number or predecessor
    could insert itself anywhere in history.
    """
    reserved = {"seq", "prev_hash", "hash", "hash_alg", "keyid"}
    supplied = reserved & set(event)
    if supplied:
        raise ValueError(f"caller may not set chain fields: {sorted(supplied)}")

    prev = log[-1] if log else None
    base = dict(event)
    base["seq"] = len(log)
    base["prev_hash"] = prev["hash"] if prev else GENESIS
    base["hash_alg"] = ALGO_UNKEYED if key is None else ALGO_KEYED
    base["keyid"] = None if key is None else key.keyid
    base["hash"] = hash_entry(base, key)
    return [*log, base]


def verify(log: list[dict], key: ChainKey | None = None) -> ChainVerdict:
    """Walk the chain and report the first entry that does not hold.

    Verification without the key is still worth doing — it catches a link break — but it cannot
    confirm the hashes, so ``verified_keyed`` is False and the caller must not report the result
    as tamper-proof. `stop-guessing ledger verify --public` exists for exactly that case.
    """
    expected_prev = GENESIS
    for i, e in enumerate(log):
        for field in ("seq", "prev_hash", "hash", "hash_alg"):
            if field not in e:
                return ChainVerdict(False, i, f"entry {i} is missing {field!r}", checked=i)
        if e["seq"] != i:
            return ChainVerdict(
                False, i, f"entry {i} carries seq {e['seq']} — entries were reordered or removed",
                checked=i,
            )
        if e["prev_hash"] != expected_prev:
            return ChainVerdict(
                False, i,
                f"entry {i} does not chain to its predecessor — an entry was altered or removed",
                checked=i,
            )
        keyed = e["hash_alg"] == ALGO_KEYED
        if keyed and key is None:
            # Link structure checked, content unverifiable. Say so rather than implying more.
            expected_prev = e["hash"]
            continue
        if not keyed and key is not None:
            return ChainVerdict(
                False, i,
                f"entry {i} is unkeyed ({ALGO_UNKEYED}) but a key was supplied — "
                "a keyed ledger with an unkeyed entry has been spliced",
                checked=i,
            )
        recomputed = hash_entry(e, key if keyed else None)
        if not hmac.compare_digest(recomputed, e["hash"]):
            return ChainVerdict(
                False, i,
                f"entry {i} content does not match its own hash — it was edited in place",
                checked=i,
            )
        expected_prev = e["hash"]

    any_keyed = any(e.get("hash_alg") == ALGO_KEYED for e in log)
    return ChainVerdict(
        intact=True,
        verified_keyed=bool(log) and any_keyed and key is not None,
        checked=len(log),
    )


def head(log: list[dict]) -> str:
    """The digest a following segment must chain to."""
    return log[-1]["hash"] if log else GENESIS
