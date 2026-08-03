"""Turn a hook payload into a custody decision.

Kept small and pure-ish on purpose: `hook_gate` owns the protocol, this owns the judgement, and
the judgement is the part that must be testable without spawning a session.
"""

from __future__ import annotations

import os
from pathlib import Path

from stop_guessing.artifacts.classify import classify_egress, classify_path, paths_in
from stop_guessing.artifacts.identity import identify
from stop_guessing.policy.engine import load
from stop_guessing.taint.state import ArtifactRef, SessionCustodyState
from stop_guessing.version import repo_root

_POLICIES = None


def ledger_path() -> Path:
    cfg = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude")
    return Path(cfg) / "stop-guessing" / "ledger" / "custody.jsonl"


def chain_key():
    from stop_guessing.attest.keys import from_env
    got = from_env()
    return got[0] if got else None


def _now() -> str:
    from datetime import UTC, datetime
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def policies():
    global _POLICIES
    if _POLICIES is None:
        _POLICIES = load(repo_root() / "policy" / "coc.policy.d")
    return _POLICIES


def state_for(session_id: str) -> tuple[SessionCustodyState, bool]:
    """Ledger-authoritative state, with the JSON file as a cache only.

    Fixes #14. This used to call `persist.load()` directly, so deleting the state file reset
    enforcement to untainted — the recorded party could clear its own taint with `rm`. The
    "ledger is authoritative" comment described a function (`reconcile_with_ledger`) that the
    deployed path never called.

    Now the ledger is replayed and wins on disagreement, and the disagreement itself is a finding
    the caller records rather than swallowing.
    """
    from stop_guessing.ledger.sink import load as load_ledger
    from stop_guessing.taint import persist

    try:
        records = load_ledger(ledger_path(), chain_key()).entries
    except Exception:  # noqa: BLE001 - no ledger yet is normal on a first run
        records = []
    if not records:
        return persist.load(session_id), True
    return persist.reconcile_with_ledger(session_id, records)


def decide(payload: dict, posture: str = "steer") -> dict | None:
    """Returns a decision dict, or None when nothing custody-relevant is happening.

    Every decision is appended to the keyed ledger before it is returned (#13). Previously the
    gate emitted a decision and wrote nothing durable, so the installed plugin produced no custody
    record at all.
    """
    tool = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    session_id = payload.get("session_id", "unknown")
    state, cache_agreed = state_for(session_id)
    ps = policies()

    command = tool_input.get("command", "") if tool == "Bash" else ""
    egress = classify_egress(command) if command else None
    is_write = tool in ("Write", "Edit", "NotebookEdit")

    candidates = paths_in(tool, tool_input)
    worst = None
    for p in candidates:
        c = classify_path(p)
        if c.classified and (worst is None or len(c.labels) > len(worst[1].labels)):
            worst = (p, c)

    if worst is None and not (egress and egress.is_egress):
        return None

    if worst is not None:
        path, c = worst
        # Stable identity (#15). `hash()` is salted per interpreter and every hook invocation is a
        # fresh interpreter, so the previous id changed on every call.
        ident = identify(path, digest_content=False)
        art_id = ident.artifact_id
        first_touch = art_id not in state.sources
        artifact = {"id": art_id, "labels": sorted(c.labels), "classified": True,
                    "first_touch": first_touch,
                    "canonical_path": ident.canonical_path,
                    "is_ledger": "stop-guessing" in ident.canonical_path
                    and "ledger" in ident.canonical_path}
    else:
        path, c, art_id, first_touch = "", None, "", False
        ident = None
        artifact = {"classified": False, "first_touch": False, "is_ledger": False}

    call = {
        "is_egress": bool(egress and egress.is_egress),
        "is_write": is_write,
        "is_own_binary": "stop-guessing" in command and "ledger" not in command,
        "markers": [m for m in ("# noodle-ok", "# risk-ok", "# custody-ok") if m in command],
    }
    ctx = state.context(posture=posture, call=call, artifact=artifact)
    d = ps.evaluate(_op_for(tool, call), ctx)

    from stop_guessing.taint import persist

    if worst is not None and d.outcome in ("allow", "ask"):
        # An `ask` that the human then approves still puts the bytes in context, so the taint is
        # recorded at the point of decision rather than waiting for an outcome we never see.
        state.touch(ArtifactRef(art_id, ident.canonical_path, ident.content_digest,
                                frozenset(c.labels)))
        persist.save(state)
    elif call["is_egress"] and d.outcome == "allow":
        state.egress()
        persist.save(state)

    reason = _render(d, artifact, state, path)
    entry = _record_decision(payload, tool, d, artifact, ident, state, call,
                             posture, cache_agreed)
    return {"outcome": d.outcome, "reason": reason,
            "determining_policy": d.determining_policy,
            "record": entry,
            "basis": {"taint": sorted(state.labels), "taint_depth": state.depth,
                      "custody_digest": state.digest}}


def _record_decision(payload, tool, d, artifact, ident, state, call, posture, cache_agreed):
    """Append the custody record for this decision. Returns its ref, or None if unrecordable."""
    from stop_guessing.ledger.sink import record

    op = _op_for(tool, call)
    used = []
    if ident is not None:
        used.append({"artifact_id": ident.artifact_id, "path": ident.canonical_path,
                     "digest": ident.content_digest, "labels": artifact.get("labels") or [],
                     "role": "input"})
    gaps = [] if cache_agreed else ["state cache disagreed with the ledger; ledger won"]
    try:
        entry = record(ledger_path(), {
            "op": op,
            "actor": "stop-guessing/hook_gate",
            "at": _now(),
            "severity": "warn" if d.outcome == "deny" else "info",
            "session_id": payload.get("session_id"),
            "prompt_id": payload.get("prompt_id"),
            "runtime_action_id": payload.get("tool_use_id"),
            "tool": {"name": tool, "source": payload.get("tool_source")},
            "posture": posture,
            "outcome": d.outcome,
            "determining_policy": d.determining_policy,
            "policy_set_digest": policies().digest,
            "resources": {"used": used},
            "basis": {"taint": sorted(state.labels), "taint_depth": state.depth,
                      "custody_digest": state.digest, "cache_agreed": cache_agreed},
            "known_gaps": gaps,
            "alterations": [],
        }, chain_key())
        return f"sg:{entry['seq']}:{entry['hash'][:16]}"
    except Exception:  # noqa: BLE001 - a refusal to write is reported by the caller's gap record
        return None


def _op_for(tool: str, call: dict) -> str:
    if call["is_egress"]:
        return "artifact.egress"
    if call["is_write"]:
        return "artifact.write"
    return "artifact.read"


def _render(d, artifact: dict, state: SessionCustodyState, path: str) -> str:
    head = f"CHAIN-OF-CUSTODY [{d.outcome}]: {d.reason}".strip()
    lines = [head]
    if artifact.get("classified") and path:
        lines.append(f"\n{path} is classified {','.join(artifact['labels'])}.")
    if d.guidance == "delegate":
        lines.append(
            "\nPreferred — delegate:\n"
            f"  stop-guessing delegate new --artifact {artifact.get('id', '')} "
            '--intent "<what you actually need>"\n'
            "Scaffolds the script and its test, runs the test, and on green runs the script under "
            "a recorded capability. You receive the script's OUTPUT and a handle — not the file.\n\n"
            "Proceeding directly is allowed and is recorded as an ISO 27037 alteration; it also "
            "raises session taint, which will deny egress later in this session."
        )
    if d.outcome == "deny" and state.sources:
        lines.append(f"\nContributing artifacts: {', '.join(sorted(state.sources))}")
        lines.append(f"Session custody digest: {state.digest[:16]}…")
    lines.append(f"\n[{d.determining_policy}]")
    return "\n".join(lines)
