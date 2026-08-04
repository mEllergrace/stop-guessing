"""The only module here that touches the filesystem.

Ported from `rockin-robin/src/rockinRobinAuditSink.ts`. The chain, alert and reconciliation logic
stay pure and independently testable; all IO risk is confined to this file.

JSON-lines, one record per line: greppable, diffable, and a crash mid-write damages one line
rather than the file.

The load-bearing behaviour is the pair of refusals. Appending onto a broken chain would pile
valid-looking records on top of an edited one until the break scrolled out of view — *the
tampering would be laundered by the very log meant to reveal it*. Appending onto a torn final
line would chain onto an incomplete predecessor. Both fail loudly and make someone look.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
from dataclasses import dataclass
from pathlib import Path

from stop_guessing.ledger.chain import (
    ALGO_KEYED,
    ChainKey,
    ChainVerdict,
    append,
    verify,
)


class LedgerError(Exception):
    """Refusal to write. Never caught internally — the point is that someone notices."""


@dataclass(frozen=True)
class LoadedLog:
    entries: list[dict]
    chain: ChainVerdict
    truncated: bool
    """True when the last line was partial — a write interrupted by a crash. The intact prefix
    is still returned, because everything before the tear is still evidence."""


def load(path: str | Path, key: ChainKey | None = None) -> LoadedLog:
    p = Path(path)
    if not p.exists():
        # A first run is not an error. Reporting one would train people to ignore the log.
        return LoadedLog([], ChainVerdict(intact=True), False)

    entries: list[dict] = []
    truncated = False
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            # Only a torn FINAL line is recoverable. A malformed line in the middle means
            # something other than a crash happened, and that is the chain's finding to report,
            # not ours to paper over.
            truncated = True
            break
    return LoadedLog(entries, verify(entries, key), truncated)


@contextlib.contextmanager
def _exclusive(path: Path):
    """Serialize the whole read -> verify -> compute-seq -> append transaction.

    Fixes #20. `O_APPEND` makes a single byte-append atomic; it does not make this transaction
    atomic. Two hook processes could read the same head, compute the same seq and prev_hash, and
    append competing records — a structurally broken chain produced by two correct callers.

    The lock file sits beside the ledger and is never truncated, so an interrupted holder releases
    it on process exit without leaving a stale marker.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = path.parent / f".{path.name}.lock"
    fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _reject_downgrade(loaded: LoadedLog, key: ChainKey | None, p: Path) -> None:
    """A keyed ledger refuses every write when the key is unavailable.

    Fixes #20. Previously `record(p, event, None)` on a keyed ledger was ACCEPTED: `load()` with
    no key checks link structure only, so the append succeeded and wrote an unkeyed entry. The
    next keyed verification then reported a splice at that index — a legal API call left the
    ledger permanently broken.
    """
    if key is not None:
        return
    if any(e.get("hash_alg") == ALGO_KEYED for e in loaded.entries):
        raise LedgerError(
            f"refusing to append to {p} without its chain key: this ledger is keyed "
            f"({ALGO_KEYED}), and an unkeyed entry would splice it. Verification would then "
            "report a break at the spliced index and every proof in the ledger would be "
            "invalidated. Supply the key, or write to a different ledger."
        )


def _reject_wrong_key(loaded, key: ChainKey | None, p: Path) -> None:
    """A key MISMATCH is not tampering, and must not be reported as tampering.

    Every entry records the `keyid` that would verify it, precisely so a reader can
    tell which key it needs. Without this check, presenting a different key made an
    intact ledger fail HMAC verification and surface as "entry 0 content does not
    match its own hash — it was edited in place", which is both false and the most
    alarming thing the tool can say.

    The cost of that confusion is specific: an operator who sees "tampered" after an
    innocent key rotation learns to dismiss the word, and dismissing it is exactly
    how a real tamper gets through.
    """
    if key is None:
        return
    recorded = {e.get("keyid") for e in loaded.entries if e.get("keyid")}
    if recorded and key.keyid not in recorded:
        raise LedgerError(
            f"refusing to append to {p}: KEY MISMATCH, not tampering. This ledger was "
            f"written under {', '.join(sorted(recorded))} and the key supplied is "
            f"{key.keyid}. A chain cannot be verified with a key it was not written "
            "under. Supply the original key, or record to a different ledger — do not "
            "assume the contents were altered."
        )


def record(path: str | Path, event: dict, key: ChainKey | None = None) -> dict:
    """Append one event, chained to whatever is already on disk.

    The whole transaction is serialized under a file lock, and a keyed ledger refuses unkeyed
    writes. Writes with O_APPEND in a single call so a reader never observes half a record, and
    fsyncs so a crash after the call cannot lose an event already reported as recorded.
    """
    p = Path(path)
    with _exclusive(p):
        return _record_locked(p, event, key)


def _record_locked(p: Path, event: dict, key: ChainKey | None) -> dict:
    loaded = load(p, key)
    _reject_downgrade(loaded, key, p)
    # Before the tamper check: a wrong key FAILS that check, and saying "tampered"
    # when the truth is "wrong key" is the more damaging error of the two.
    _reject_wrong_key(loaded, key, p)

    if not loaded.chain.intact:
        raise LedgerError(
            f"refusing to append to a tampered ledger at {p}: "
            f"{loaded.chain.reason or 'chain broken'} (entry {loaded.chain.broken_at}). "
            "Appending would bury the break under new entries. Preserve this file and "
            "investigate before recording anything further."
        )
    if loaded.truncated:
        raise LedgerError(
            f"refusing to append to a truncated ledger at {p}: the final record is partial, "
            "so a new entry would chain onto an incomplete predecessor. Repair or archive it "
            "first."
        )

    written = append(loaded.entries, event, key)[-1]
    p.parent.mkdir(parents=True, exist_ok=True)
    line = (json.dumps(written, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, line.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    return written


def record_many(path: str | Path, events: list[dict], key: ChainKey | None = None) -> list[dict]:
    """Append a batch under ONE lock, so a concurrent writer cannot interleave into the run."""
    p = Path(path)
    with _exclusive(p):
        return [_record_locked(p, ev, key) for ev in events]
