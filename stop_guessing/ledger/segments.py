"""Seal and archive, rather than rotate and truncate.

no-noodles' `lib_observe.sh` caps `observations.jsonl` at 5000 lines and drops the oldest with
`tail`. That is fine for an observation log and fatal for a custody ledger: truncation destroys
the earliest evidence *and* breaks the chain that proves the rest.

Sealing instead: the active segment is closed, its digest recorded, and the next segment chains
its genesis to that digest. History becomes a sequence of sealed files, each internally verifiable
and each linked to its predecessor — so verifying the whole record does not require holding it all
open, and no evidence is ever discarded to make room.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from stop_guessing.artifacts.digest import bytes_digest, file_digest
from stop_guessing.ledger.chain import GENESIS, ChainKey, verify
from stop_guessing.ledger.sink import LedgerError, load

SEAL_SUFFIX = ".seal.json"


@dataclass(frozen=True)
class Seal:
    """The closing record of one segment, and the genesis link of the next."""

    segment: str
    path: str
    records: int
    first_seq: int
    last_seq: int
    head_hash: str
    file_digest: str
    prev_seal_digest: str
    sealed_at: str

    def to_dict(self) -> dict:
        return {
            "segment": self.segment,
            "path": self.path,
            "records": self.records,
            "first_seq": self.first_seq,
            "last_seq": self.last_seq,
            "head_hash": self.head_hash,
            "file_digest": self.file_digest,
            "prev_seal_digest": self.prev_seal_digest,
            "sealed_at": self.sealed_at,
        }

    def digest(self) -> str:
        return bytes_digest(
            json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode()
        )


def segment_name(index: int) -> str:
    return f"seg-{index:06d}"


def seal(
    path: str | Path,
    *,
    at: str,
    key: ChainKey | None = None,
    prev_seal_digest: str = GENESIS,
    index: int = 0,
) -> Seal:
    """Close a segment. Refuses to seal a ledger that does not verify.

    Sealing a broken chain would stamp a digest onto a record we already know is wrong, giving
    it the appearance of having been checked.
    """
    p = Path(path)
    loaded = load(p, key)
    if not loaded.chain.intact:
        raise LedgerError(
            f"refusing to seal {p}: {loaded.chain.reason} (entry {loaded.chain.broken_at}). "
            "Sealing a broken chain would certify a record we know is wrong."
        )
    if loaded.truncated:
        raise LedgerError(f"refusing to seal {p}: the final record is partial")
    if not loaded.entries:
        raise LedgerError(f"refusing to seal {p}: nothing to seal")

    fd = file_digest(p)
    if fd is None:
        raise LedgerError(f"refusing to seal {p}: cannot digest the segment file")

    s = Seal(
        segment=segment_name(index),
        path=str(p),
        records=len(loaded.entries),
        first_seq=loaded.entries[0]["seq"],
        last_seq=loaded.entries[-1]["seq"],
        head_hash=loaded.entries[-1]["hash"],
        file_digest=fd,
        prev_seal_digest=prev_seal_digest,
        sealed_at=at,
    )
    Path(str(p) + SEAL_SUFFIX).write_text(
        json.dumps(s.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return s


def load_seal(path: str | Path) -> Seal | None:
    p = Path(str(path) + SEAL_SUFFIX)
    if not p.is_file():
        return None
    d = json.loads(p.read_text(encoding="utf-8"))
    return Seal(**d)


def verify_sealed(path: str | Path, key: ChainKey | None = None) -> dict:
    """Check a sealed segment against its seal: chain, file digest, head, and record count."""
    p = Path(path)
    s = load_seal(p)
    if s is None:
        return {"ok": False, "findings": [f"no seal beside {p}"]}

    findings: list[str] = []
    loaded = load(p, key)
    if not loaded.chain.intact:
        findings.append(f"chain broken at {loaded.chain.broken_at}: {loaded.chain.reason}")
    current = file_digest(p)
    if current != s.file_digest:
        findings.append(
            f"segment file digest changed since sealing (sealed {s.file_digest[:16]}…, "
            f"now {(current or 'unreadable')[:16]}…) — the sealed file was modified"
        )
    # Read defensively: a malformed record appended after sealing must produce a FINDING, not a
    # KeyError. A verifier that crashes on hostile input is a denial-of-verification — the
    # attacker gets "the tool errored" instead of "the segment was tampered with".
    if loaded.entries:
        actual_head = loaded.entries[-1].get("hash")
        if actual_head is None:
            findings.append(
                "the final record has no hash field — a malformed record was appended "
                "after sealing"
            )
        elif actual_head != s.head_hash:
            findings.append(
                "head hash does not match the seal — records were appended after sealing"
            )
    if len(loaded.entries) != s.records:
        findings.append(
            f"seal records {s.records} entries, file has {len(loaded.entries)} — "
            "records were added or removed after sealing"
        )
    return {"ok": not findings, "findings": findings, "seal": s.to_dict()}


def verify_series(paths: list[str | Path], key: ChainKey | None = None) -> dict:
    """Verify a sequence of sealed segments and that each links to its predecessor's seal."""
    findings: list[str] = []
    expected_prev = GENESIS
    checked = 0
    for i, p in enumerate(paths):
        result = verify_sealed(p, key)
        if not result["ok"]:
            findings.extend(f"{segment_name(i)}: {f}" for f in result["findings"])
            continue
        s = Seal(**result["seal"])
        if s.prev_seal_digest != expected_prev:
            findings.append(
                f"{segment_name(i)}: chains to {s.prev_seal_digest[:16]}… but the previous "
                f"seal digests to {expected_prev[:16]}… — a segment was replaced or removed"
            )
        expected_prev = s.digest()
        checked += s.records
    return {"ok": not findings, "findings": findings, "segments": len(paths), "records": checked}


def verify_all(log: list[dict], key: ChainKey | None = None) -> dict:
    """Convenience: chain verdict as a plain dict, for CLI and record embedding."""
    return verify(log, key).to_dict()
