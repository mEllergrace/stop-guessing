"""Turn a hook payload into a custody decision.

Kept small and pure-ish on purpose: `hook_gate` owns the protocol, this owns the judgement, and
the judgement is the part that must be testable without spawning a session.
"""

from __future__ import annotations

from stop_guessing.artifacts.classify import classify_egress, classify_path, paths_in
from stop_guessing.policy.engine import load
from stop_guessing.taint.state import ArtifactRef, SessionCustodyState
from stop_guessing.version import repo_root

_POLICIES = None


def policies():
    global _POLICIES
    if _POLICIES is None:
        _POLICIES = load(repo_root() / "policy" / "coc.policy.d")
    return _POLICIES


def state_for(session_id: str) -> SessionCustodyState:
    """Load persisted state.

    NOT a process-local dict. Every PreToolUse invocation is a fresh process, so an in-memory
    cache means taint never accumulates and the twelve-reads-then-egress case never fires. That
    was a real defect: every proof passed while the deployed path did nothing.
    """
    from stop_guessing.taint import persist

    return persist.load(session_id)


def decide(payload: dict, posture: str = "steer") -> dict | None:
    """Returns a decision dict, or None when nothing custody-relevant is happening."""
    tool = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    session_id = payload.get("session_id", "unknown")
    state = state_for(session_id)
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
        art_id = f"art_{abs(hash(path)) % 10**8}"
        first_touch = art_id not in state.sources
        artifact = {"id": art_id, "labels": sorted(c.labels), "classified": True,
                    "first_touch": first_touch,
                    "is_ledger": "stop-guessing" in path and "ledger" in path}
    else:
        path, c, art_id, first_touch = "", None, "", False
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
        state.touch(ArtifactRef(art_id, path, None, frozenset(c.labels)))
        persist.save(state)
    elif call["is_egress"] and d.outcome == "allow":
        state.egress()
        persist.save(state)

    reason = _render(d, artifact, state, path)
    return {"outcome": d.outcome, "reason": reason,
            "determining_policy": d.determining_policy,
            "basis": {"taint": sorted(state.labels), "taint_depth": state.depth,
                      "custody_digest": state.digest}}


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
