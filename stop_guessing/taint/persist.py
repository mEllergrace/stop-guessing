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
    """Project-local by default. See `stop_guessing.paths` for why this moved.

    This resolved under `$CLAUDE_CONFIG_DIR`, which belongs to the agent and is shared by every
    session and project on that profile. It accumulated 31 state files, ~24 of them real session
    UUIDs from whatever projects happened to be open — and since the record carries `session_id`
    with no `cwd`, not one of them could be attributed to a project. `$STOP_GUESSING_HOME` still
    points it anywhere, so a deliberately shared store remains available.
    """
    from stop_guessing.paths import state_dir as _resolved

    return _resolved()


def legacy_state_dir() -> Path:
    """The pre-move location. Kept because accumulated evidence is not disposable state."""
    base = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude")
    return Path(base) / "stop-guessing" / "state"


def _path(session_id: str) -> Path:
    """One file per session, with no way for two sessions to land on the same one.

    #62 (SG-HARD-029). This sanitised every non-alphanumeric character to ``_`` and then truncated
    to 120 characters, so ``a/b`` and ``a:b`` mapped to the same file, as did any two ids sharing a
    120-character prefix. Two sessions sharing a state file mix their taint — and taint is what
    denies an egress, so a collision is a security-relevant outcome reached by a filename rule.

    A digest of the FULL id cannot collide by construction. A short readable prefix is kept in
    front of it so the directory is still greppable by eye, and `save()` writes the original id
    inside the file so a mismatch is detectable rather than assumed.
    """
    import hashlib

    digest = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:32]
    readable = "".join(c if c.isalnum() or c in "-_" else "_" for c in session_id)[:40]
    return state_dir() / f"{readable}.{digest}.json"


def save(state: SessionCustodyState) -> Path:
    """Write atomically. A half-written state file would silently under-report taint."""
    p = _path(state.session_id)
    p.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        p.parent.chmod(0o700)
    body = {
        "_version": STATE_VERSION,
        "session_id": state.session_id,
        # The project this state belongs to. Its absence was the other half of the shared-store
        # defect: 31 pooled state files recorded `session_id` and nothing else, so not one of them
        # could be attributed to a project even in principle. A provenance record that cannot say
        # where it came from is doing half its job.
        "project": str(Path.cwd()),
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
    # #62: the file stores the id it was written for. If it disagrees with the id being loaded,
    # this is another session's state and using it would import that session's taint. Start clean
    # rather than merge — a wrong answer here silently changes what gets allowed to egress.
    stored = body.get("session_id")
    if stored is not None and stored != session_id:
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
