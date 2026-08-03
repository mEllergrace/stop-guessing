"""Persist session custody state across hook processes.

**This module exists because of a real defect.** Accumulation — the whole point of the tool — was
implemented as a process-local dict. Every proof passed, because a proof procedure runs in one
process. In production every `PreToolUse` invocation is a *fresh process*, so the state was empty
every time and the twelve-reads-then-egress case never fired. The mechanism was correct and the
system did not work.

That is the DEMM-Bench problem in miniature: proving the container is not proving the answer. The
fix is here; the harder fix is in the proof, which now drives the real hook across separate
processes and would fail if this module were removed.

**The ledger stays authoritative.** This file is a cache. `rebuild()` in `taint.state` replays
records and is the recovery path; if the cache is missing, corrupt, or disagrees, the ledger wins.
A cache that could outvote the evidence would be a second, forgeable source of truth.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import tempfile
from pathlib import Path

from stop_guessing.taint.state import ArtifactRef, SessionCustodyState

STATE_VERSION = 1


def state_dir() -> Path:
    base = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude")
    return Path(base) / "stop-guessing" / "state"


def _path(session_id: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in session_id)[:120]
    return state_dir() / f"{safe}.json"


def save(state: SessionCustodyState) -> Path:
    """Write atomically. A half-written state file would silently under-report taint."""
    p = _path(state.session_id)
    p.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        p.parent.chmod(0o700)
    body = {
        "_version": STATE_VERSION,
        "session_id": state.session_id,
        "labels": sorted(state.labels),
        "sources": {k: v.to_dict() for k, v in state.sources.items()},
        "touched": state.touched,
        "since_last_egress": state.since_last_egress,
        "compaction_generation": state.compaction_generation,
        "edges": [list(e) for e in state.edges],
        "digest": state.digest,
    }
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".state-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(body, fh, sort_keys=True)
        os.replace(tmp, p)
        p.chmod(0o600)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return p


def load(session_id: str) -> SessionCustodyState:
    """Load, or return a fresh state. A corrupt cache is discarded, never trusted."""
    p = _path(session_id)
    if not p.is_file():
        return SessionCustodyState(session_id)
    try:
        body = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return SessionCustodyState(session_id)
    if body.get("_version") != STATE_VERSION:
        return SessionCustodyState(session_id)

    state = SessionCustodyState(
        session_id=body.get("session_id", session_id),
        labels=frozenset(body.get("labels") or {"public"}),
        touched=body.get("touched", 0),
        since_last_egress=body.get("since_last_egress", 0),
        compaction_generation=body.get("compaction_generation", 0),
        edges=[tuple(e) for e in body.get("edges") or []],
    )
    for aid, d in (body.get("sources") or {}).items():
        state.sources[aid] = ArtifactRef(
            artifact_id=d.get("artifact_id", aid), path=d.get("path", ""),
            digest=d.get("digest"), labels=frozenset(d.get("labels") or {"public"}),
        )
    # A cache whose digest does not match its own contents is not a cache; drop it.
    if body.get("digest") and body["digest"] != state.digest:
        return SessionCustodyState(session_id)
    return state


@contextlib.contextmanager
def exclusive(session_id: str):
    """Hold the session's lock across load-modify-save.

    Fixes #24. `os.replace` prevents a partial file; it does nothing about lost updates. Two
    processes could load the same state, each add a different artifact, each save, and the second
    silently discard the first — which is exactly how taint goes missing under parallel agents.
    """
    d = state_dir()
    d.mkdir(parents=True, exist_ok=True)
    lock = d / f".{_path(session_id).name}.lock"
    fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def clear(session_id: str) -> None:
    _path(session_id).unlink(missing_ok=True)


def reconcile_with_ledger(session_id: str, records: list[dict]) -> tuple[SessionCustodyState, bool]:
    """Rebuild from the ledger and compare. The ledger wins on disagreement.

    Returns (authoritative_state, agreed). A disagreement is a finding — the cache was tampered
    with, truncated, or lost — and the caller records it rather than silently continuing.
    """
    from stop_guessing.taint.state import rebuild

    cached = load(session_id)
    authoritative = rebuild(records, session_id)
    agreed = cached.digest == authoritative.digest
    if not agreed:
        save(authoritative)
    return authoritative, agreed
