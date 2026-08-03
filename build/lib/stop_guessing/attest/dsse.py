"""DSSE — Dead Simple Signing Envelope, the in-toto attestation wrapper.

Pre-Authentication Encoding exists so a signature over a payload cannot be reinterpreted as a
signature over a different payload type. Implemented per the DSSE spec: the signed material is

    "DSSEv1" SP len(payloadType) SP payloadType SP len(payload) SP payload

with lengths in ASCII decimal, so no field can be extended into its neighbour.

Signing here is HMAC by default — symmetric, local, offline. That is honest for a
single-custodian ledger and is reported as such: `verification.signature.scheme` says
`hmac-sha256`, not `ed25519`, so nobody reads it as public-verifiable. Ed25519 lands with the
segment-certification work at M7.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any

PAYLOAD_TYPE = "application/vnd.in-toto+json"


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding."""
    return b"DSSEv1 %d %s %d %s" % (
        len(payload_type), payload_type.encode(), len(payload), payload,
    )


def canonical(statement: dict[str, Any]) -> bytes:
    return json.dumps(statement, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sign(statement: dict, key: bytes, keyid: str,
         payload_type: str = PAYLOAD_TYPE) -> dict:
    payload = canonical(statement)
    sig = hmac.new(key, pae(payload_type, payload), hashlib.sha256).digest()
    return {
        "payloadType": payload_type,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [{"keyid": keyid, "sig": base64.b64encode(sig).decode(),
                        "scheme": "hmac-sha256"}],
    }


def verify(envelope: dict, key: bytes) -> tuple[bool, str]:
    """Returns (ok, reason). Never raises on a malformed envelope — that is a finding."""
    try:
        payload = base64.b64decode(envelope["payload"])
        payload_type = envelope["payloadType"]
        sigs = envelope["signatures"]
    except (KeyError, TypeError, ValueError) as exc:
        return False, f"malformed envelope: {exc}"
    if not sigs:
        return False, "envelope carries no signatures"
    expected = hmac.new(key, pae(payload_type, payload), hashlib.sha256).digest()
    for s in sigs:
        try:
            if hmac.compare_digest(base64.b64decode(s["sig"]), expected):
                return True, f"verified under keyid {s.get('keyid')}"
        except (KeyError, ValueError):
            continue
    return False, "no signature verified under the supplied key"


def payload_of(envelope: dict) -> dict:
    return json.loads(base64.b64decode(envelope["payload"]))
