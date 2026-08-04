"""Turn a hook payload into a custody decision.

Kept small and pure-ish on purpose: `hook_gate` owns the protocol, this owns the judgement, and
the judgement is the part that must be testable without spawning a session.
"""

from __future__ import annotations

import json
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
    from stop_guessing.recorder import client
    from stop_guessing.taint import persist

    cfg = Path(os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude"))
    # Prefer the recorder's own derivation: the party that owns the history derives the state.
    remote = client.custody_state(cfg, session_id)
    if remote is not None:
        cached = persist.load(session_id)
        return _state_from(remote, session_id), cached.digest == remote["digest"]

    try:
        records = load_ledger(ledger_path(), chain_key()).entries
    except Exception:  # noqa: BLE001 - no ledger yet is normal on a first run
        records = []
    if not records:
        return persist.load(session_id), True
    return persist.reconcile_with_ledger(session_id, records)


def _state_from(remote: dict, session_id: str) -> SessionCustodyState:
    st = SessionCustodyState(session_id, labels=frozenset(remote["labels"]),
                             touched=remote.get("touched", 0),
                             since_last_egress=remote.get("since_last_egress", 0))
    for aid, d in (remote.get("sources") or {}).items():
        st.sources[aid] = ArtifactRef(aid, d.get("path", ""), d.get("digest"),
                                      frozenset(d.get("labels") or {"public"}))
    return st


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
    """Append the custody record for this decision, in the §7 predicate shape.

    The gate previously wrote a flat ad-hoc dict and never used `ledger.entry.CustodyRecord` — so
    the deployed path produced records that failed the project's OWN sufficiency measure: 0 of 4
    governance questions answerable, because none of the eight evidence regimes was populated.
    Another instance of #13: the builder existed and the deployed path did not use it.
    """
    from stop_guessing.ledger.entry import CustodyRecord, RecordInvalid

    op = _op_for(tool, call)
    used = []
    subjects = []
    if ident is not None:
        used.append({"artifact_id": ident.artifact_id, "path": ident.canonical_path,
                     "digest": ident.content_digest, "labels": artifact.get("labels") or [],
                     "role": "input"})
        subjects.append({
            "name": f"file://{ident.canonical_path}",
            "uri": f"file://{ident.canonical_path}",
            "digest": {"sha256": ident.content_digest or ""},
            "annotations": {
                "csa.coc/artifact_id": ident.artifact_id,
                "csa.coc/classification": artifact.get("labels") or [],
                "csa.coc/digest_scope": "absent" if ident.content_digest is None else "full",
            },
        })

    gaps = [] if cache_agreed else ["state cache disagreed with the ledger; ledger won"]
    if ident is not None and ident.content_digest is None:
        gaps.append("artifact content was not digested at decision time (PreToolUse budget)")
    session_id = str(payload.get("session_id") or "unknown")
    prompt_id = payload.get("prompt_id")

    try:
        stmt = CustodyRecord(
            op=op,
            agent_id=f"spiffe://local/claude-code/session/{session_id}/agent/main",
            runtime_action_id=str(payload.get("tool_use_id") or f"{op}:{_now()}"),
            operator={"identity": f"{os.environ.get('USER', 'unknown')}@{_host()}",
                      "uid": os.getuid(), "host": _host()},
            session_id=session_id,
            posture=posture,
            outcome=d.outcome,
            channel="hookSpecificOutput.permissionDecision",
            at=_now(),
            recorded_at=_now(),
            record_id=f"sg:{session_id}:{payload.get('tool_use_id') or op}",
            method_kind=("denied" if d.outcome == "deny" else
                         "delegated-script" if call.get("delegated_script") else "direct-model"),
            input_digest=_input_digest(payload),
            policy_set_digest=policies().digest,
            determining_policy=d.determining_policy,
            known_gaps=gaps,
            extra={
                "actor": {"acted_on_behalf_of": {
                    "prov_type": "prov:Person",
                    "human_id": f"local:{os.environ.get('USER', 'unknown')}",
                    "authority": "prompt", "prompt_id": prompt_id,
                    "delegation_depth": 0}},
                "authority": {"capability": {
                    "grant_id": f"cap:{posture}", "granted_by": d.determining_policy,
                    "scope": [op]}},
                "action": {"tool": {"name": tool, "source": payload.get("tool_source")},
                           "gen_ai": {"operation_name": "execute_tool", "tool_name": tool,
                                      "tool_call_id": payload.get("tool_use_id")}},
                "decision": {"reason": d.reason, "basis": {
                    "taint_labels": sorted(state.labels), "taint_depth": state.depth,
                    "taint_sources": sorted(state.sources),
                    "session_custody_digest": state.digest,
                    "cache_agreed": cache_agreed,
                    "counterfactual": d.counterfactual}},
                "resources": {"used": used},
                "lifecycle": {"prompt_id": prompt_id, "cwd": payload.get("cwd"),
                              "transcript_path": payload.get("transcript_path")},
                # The algo is asked, not guessed. With a daemon the hook holds no key, so
                # `chain_key()` is None while the record is in fact keyed — guessing here made
                # the record UNDERSTATE its own strength, which is the same class of error as
                # overstating it: the record stopped describing reality.
                "verification": {"chain": {"algo": _chain_algo()},
                                 "recorder": {"writer": "hook_gate", "isolation_tier": 0}},
            },
        ).build(subjects=subjects)
    except RecordInvalid:
        return None

    # Through the recorder, not straight to the file. When a daemon is running the hook holds no
    # chain key and does not own the ledger; when it is not, the fallback records tier 0 and why.
    from stop_guessing.recorder import client

    cfg = Path(os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude"))
    tier, _why = client.isolation_tier(cfg)
    stmt["predicate"]["verification"]["recorder"] = {
        "writer": "cocd" if tier > 0 else "hook_gate", "isolation_tier": tier,
    }
    stmt["predicate"]["verification"]["strength"] = _strength_for(stmt["predicate"])
    out = client.append(cfg, {"op": op, "at": _now(),
                              "actor": "stop-guessing/hook_gate",
                              "severity": "warn" if d.outcome == "deny" else "info",
                              "statement": stmt,
                              # Flat mirrors, so a reader does not have to walk the predicate
                              # to answer the common questions.
                              "session_id": session_id,
                              "outcome": d.outcome,
                              "resources": {"used": used}},
                        fallback_key=chain_key())
    return out.ref


def _strength_for(pred: dict) -> str:
    from stop_guessing.ledger.entry import strength

    return strength(pred)


def _chain_algo() -> str:
    """What the ledger is ACTUALLY chained with, from whoever is doing the chaining."""
    from stop_guessing.recorder import client

    cfg = Path(os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude"))
    info = client.daemon_info(cfg)
    if info and info.get("ok"):
        return "hmac-sha256" if info.get("keyed") else "sha256"
    return "hmac-sha256" if chain_key() else "sha256"


def _host() -> str:
    import socket
    try:
        return socket.gethostname()
    except OSError:
        return "unknown"


def _input_digest(payload: dict) -> str:
    from stop_guessing.artifacts.digest import bytes_digest
    return "sha256:" + bytes_digest(
        json.dumps(payload.get("tool_input") or {}, sort_keys=True, default=str).encode())


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
