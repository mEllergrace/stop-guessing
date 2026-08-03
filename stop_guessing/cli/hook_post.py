"""PostToolUse — did the approved action actually run, and what came back?

**Fixes the second half of #13.** Only `PreToolUse` was registered, so nothing recorded whether a
permitted tool executed, whether it succeeded, what it returned, or which artifacts it generated.
A ledger of *requests* cannot answer "which bytes moved" — it answers "what was asked".

Two things this establishes that PreToolUse structurally cannot:

- **Execution corroboration.** The pre-record is the recorder's own dispatch; this is the result.
  A permitted decision with no matching result is an unreported execution, which is exactly what
  `reconcile()` is for — the same rule as `rockin-robin`: *an audit trail owned by the audited
  party is not an audit trail.*
- **Derivation.** A write whose session already holds taint produces an output that carries it.
  That edge is the thing no surveyed tool records, and it can only be drawn once the output exists.

Never blocks. PostToolUse runs after the fact; the only thing it can do by failing is destroy the
session, so every path returns 0 and any failure is recorded as a gap.
"""

from __future__ import annotations

import json
import sys

from stop_guessing.artifacts.classify import classify_path, paths_in
from stop_guessing.artifacts.identity import identify
from stop_guessing.cli.gate import _now, chain_key, ledger_path, state_for
from stop_guessing.taint.labels import is_classified, join


def record_result(payload: dict) -> dict | None:
    """Append the `tool.result` record, plus a derivation edge when one is real."""
    from stop_guessing.ledger.sink import record
    from stop_guessing.taint import persist
    from stop_guessing.taint.state import ArtifactRef

    tool = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    result = payload.get("tool_result", payload.get("tool_response")) or {}
    session_id = payload.get("session_id", "unknown")
    key = chain_key()

    success = True
    if isinstance(result, dict):
        success = bool(result.get("success", True)) and not result.get("error")

    state, cache_agreed = state_for(session_id)

    generated, used, edges = [], [], []
    is_write = tool in ("Write", "Edit", "NotebookEdit")
    with persist.exclusive(session_id):
        for raw in paths_in(tool, tool_input):
            ident = identify(raw, digest_content=True)
            if not ident.exists:
                continue
            labels = classify_path(ident.canonical_path).labels
            ref = {"artifact_id": ident.artifact_id, "path": ident.canonical_path,
                   "digest": ident.content_digest, "labels": sorted(labels)}
            if is_write:
                # An output written while the session holds taint inherits it. This is the
                # derivation edge, and it is only drawable once the output exists.
                inherited = join(labels, state.labels)
                ref["labels"] = sorted(inherited)
                generated.append(ref)
                for src in state.sources.values():
                    edges.append({"generated": ident.artifact_id, "source": src.artifact_id,
                                  "via": f"{tool}:{ident.canonical_path}"})
                state.touch(ArtifactRef(ident.artifact_id, ident.canonical_path,
                                        ident.content_digest, frozenset(inherited)))
            else:
                used.append(ref)
                if is_classified(labels):
                    state.touch(ArtifactRef(ident.artifact_id, ident.canonical_path,
                                            ident.content_digest, frozenset(labels)))
        persist.save(state)

    op = "artifact.derive" if (is_write and edges) else ("artifact.write" if is_write
                                                        else "tool.result")
    try:
        entry = record(ledger_path(), {
            "op": op,
            "actor": "stop-guessing/hook_post",
            "at": _now(),
            "severity": "info" if success else "warn",
            "session_id": session_id,
            "runtime_action_id": payload.get("tool_use_id"),
            "tool": {"name": tool},
            "executed": True,
            "success": success,
            "result_bytes": len(json.dumps(result)) if result else 0,
            "resources": {"used": used, "generated": generated, "derived_from": edges},
            "basis": {"taint": sorted(state.labels), "taint_depth": state.depth,
                      "custody_digest": state.digest, "cache_agreed": cache_agreed},
            "known_gaps": [] if cache_agreed else
                          ["state cache disagreed with the ledger; ledger won"],
            "alterations": [],
        }, key)
        return entry
    except Exception:  # noqa: BLE001
        return None


def main(argv: list[str] | None = None) -> int:
    raw = sys.stdin.buffer.read()
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return 0
    try:
        record_result(payload)
    except Exception as exc:  # noqa: BLE001
        from stop_guessing.cli.hook_gate import _record_gap

        _record_gap(payload, exc)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
