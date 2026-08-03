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

import json
import os
from dataclasses import dataclass
from pathlib import Path

from stop_guessing.ledger.chain import ChainKey, ChainVerdict, append, verify


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


def record(path: str | Path, event: dict, key: ChainKey | None = None) -> dict:
    """Append one event, chained to whatever is already on disk.

    Writes with O_APPEND in a single call so a concurrent writer cannot interleave a partial
    record, and fsyncs so a crash after the call cannot lose an event we have already reported
    as recorded.
    """
    p = Path(path)
    loaded = load(p, key)

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
    """Append a batch. Still one chain-load per call, so a mid-batch break stops the batch."""
    written = []
    for ev in events:
        written.append(record(path, ev, key))
    return written
