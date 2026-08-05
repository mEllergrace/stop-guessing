"""Session lifecycle events — the custody a per-tool-call record cannot carry.

#42/#81 (SG-HARD-048). The plugin registered `PreToolUse` and `PostToolUse` out of 31 documented
events, so the ledger was complete per tool call and had nothing at all to say per session: no
boundary, no prompt lineage, no compaction checkpoint, no reconciliation at the end, and no record
whatsoever of a tool call that FAILED. Three claims (11, 13, 14) named hooks that did not exist,
which is how a proof harness demonstrates a primitive the installed system never invokes.

Each event here closes a specific evidentiary gap rather than being registered for the count:

    SessionStart        recorder self-check, chain verify, CAIQ version inspect  -> `session.open`
    UserPromptSubmit    the root of every IAM-AG-03 delegation chain             -> `prompt.submit`
    PostToolUseFailure  the outcome PostToolUse structurally cannot see          -> `tool.result`
    PreCompact          custody digest before context is discarded               -> `custody.checkpoint`
    SubagentStop        join a child agent's taint back into the parent          -> `agent.merge`
    Stop               reconcile dispatches against results for the turn         -> `tool.reconcile`
    SessionEnd          seal the segment and close the session                   -> `session.close`

**None of these blocks.** They are observers; every one returns 0 whatever happens, because a
lifecycle recorder that can fail a session is a recorder that gets uninstalled. Failures are
recorded as gaps through the same path the gate uses.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _cfg() -> Path:
    return Path(os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude"))


def _emit(event: dict) -> str | None:
    """Append through the recorder, falling back exactly as the gate does."""
    from stop_guessing.attest.keys import discover
    from stop_guessing.recorder import client

    cfg = _cfg()
    got = discover(config_dir=cfg)
    event.setdefault("known_gaps", [])
    event.setdefault("alterations", [])
    event.setdefault("at", _now())
    event.setdefault("actor", "stop-guessing/lifecycle")
    event.setdefault("severity", "info")
    return client.append(cfg, event, fallback_key=got[0] if got else None).ref


def _session(payload: dict) -> str:
    return payload.get("session_id") or "unknown"


# ── the events ───────────────────────────────────────────────────────────────


def session_start(payload: dict) -> str | None:
    """Open the session, and say what state the recorder was in when it opened.

    `source=compact` means the context was just discarded, so this is also where a rebuilt custody
    state is compared against the checkpoint written by PreCompact.
    """
    from stop_guessing.ledger.sink import load
    from stop_guessing.recorder.client import isolation_tier

    cfg = _cfg()
    tier, why = isolation_tier(cfg)
    detail = {"source": payload.get("source"), "isolation_tier": tier, "isolation_reason": why}

    from stop_guessing.attest.keys import discover
    from stop_guessing.recorder.daemon import ledger_path

    got = discover(config_dir=cfg)
    led = ledger_path(cfg)
    gaps = []
    if led.is_file():
        loaded = load(led, got[0] if got else None)
        detail["ledger_records"] = len(loaded.entries)
        detail["chain_intact"] = loaded.chain.intact
        detail["chain_usable"] = loaded.usable
        if not loaded.usable:
            gaps.append(f"ledger not usable at session start: {loaded.chain.reason}")
    else:
        detail["ledger_records"] = 0
    if tier == 0:
        gaps.append("isolation tier 0: no recorder daemon; records written in-process")

    return _emit({
        "op": "session.open",
        "session_id": _session(payload),
        "detail": json.dumps(detail, sort_keys=True),
        "known_gaps": gaps,
        "severity": "critical" if gaps else "info",
    })


def prompt_submit(payload: dict) -> str | None:
    """The root of the delegation chain: every later action acted on behalf of this request."""
    from stop_guessing.artifacts.digest import bytes_digest

    prompt = payload.get("prompt") or ""
    return _emit({
        "op": "prompt.submit",
        "session_id": _session(payload),
        # The prompt DIGEST, never the prompt. A custody ledger that quietly accumulated every
        # prompt would be a transcript, and a transcript is the thing this tool exists to not need.
        "detail": json.dumps({
            "prompt_digest": "sha256:" + bytes_digest(prompt.encode("utf-8")),
            "prompt_chars": len(prompt),
            "prompt_id": payload.get("prompt_id"),
        }, sort_keys=True),
    })


def tool_failed(payload: dict) -> str | None:
    """#42 (SG-HARD-009): the outcome `PostToolUse` structurally cannot observe.

    Claude Code delivers failures on a different event, so a hook registered only on PostToolUse
    records successes and is silent on every error, timeout, permission denial and interruption.
    An evidence log that contains only the calls that worked is not an evidence log.
    """
    tool = payload.get("tool_name") or "?"
    return _emit({
        "op": "tool.result",
        "session_id": _session(payload),
        "severity": "warning",
        "detail": json.dumps({
            "tool": tool,
            "success": False,
            "tool_use_id": payload.get("tool_use_id"),
            "error_shape": type(payload.get("tool_error")).__name__,
            "error_chars": len(str(payload.get("tool_error") or "")),
        }, sort_keys=True),
    })


def pre_compact(payload: dict) -> str | None:
    """Checkpoint custody state before the context that produced it is discarded."""
    from stop_guessing.taint import persist

    sid = _session(payload)
    state = persist.load(sid)
    return _emit({
        "op": "custody.checkpoint",
        "session_id": sid,
        "detail": json.dumps({
            "session_custody_digest": state.digest,
            "labels": sorted(state.labels),
            "touched": state.touched,
            "compaction_generation": state.compaction_generation,
        }, sort_keys=True),
    })


def subagent_stop(payload: dict) -> str | None:
    """Join a child agent's taint back into the parent. Labels only ever accumulate."""
    from stop_guessing.taint import persist

    sid = _session(payload)
    child = payload.get("agent_id") or payload.get("subagent_id") or "unknown-child"
    state = persist.load(sid)
    return _emit({
        "op": "agent.merge",
        "session_id": sid,
        "detail": json.dumps({
            "child_agent": child,
            "parent_labels_after": sorted(state.labels),
            "parent_digest": state.digest,
        }, sort_keys=True),
    })


def turn_stop(payload: dict) -> str | None:
    """#82 (SG-HARD-049): reconcile what the recorder dispatched against what came back.

    `ledger/reconcile.py` was built, tested, and called by nothing — the one mechanism that would
    catch a fabricated or replayed execution was not running. This is where it runs.
    """
    from stop_guessing.attest.keys import discover
    from stop_guessing.ledger.reconcile import Dispatch, Reported, reconcile
    from stop_guessing.ledger.sink import load
    from stop_guessing.recorder.daemon import ledger_path

    cfg = _cfg()
    sid = _session(payload)
    got = discover(config_dir=cfg)
    led = ledger_path(cfg)
    if not led.is_file():
        return None

    entries = load(led, got[0] if got else None).entries
    dispatches, results = [], []
    for e in entries:
        if e.get("session_id") != sid:
            continue
        try:
            detail = json.loads(e.get("detail") or "{}")
        except (ValueError, TypeError):
            detail = {}
        tuid = detail.get("tool_use_id")
        if not tuid:
            continue
        if e.get("op") == "tool.decision":
            dispatches.append(Dispatch(instance_id=tuid, seq=e.get("seq", 0),
                                       action=detail.get("tool", "?"), nonce=detail.get("nonce")))
        elif e.get("op") == "tool.result":
            results.append(Reported(instance_id=tuid, action=detail.get("tool", "?"),
                                    nonce=detail.get("nonce")))

    rec = reconcile(dispatches, results)
    findings = rec.findings if hasattr(rec, "findings") else []
    return _emit({
        "op": "tool.reconcile",
        "session_id": sid,
        "severity": "critical" if findings else "info",
        "detail": json.dumps({
            "dispatched": len(dispatches), "reported": len(results),
            "verified": getattr(rec, "verified", None),
            "findings": [str(f) for f in findings],
        }, sort_keys=True),
        "known_gaps": [str(f) for f in findings],
    })


def session_end(payload: dict) -> str | None:
    """Close the session. Sealing is deliberately NOT done here — see the comment."""
    sid = _session(payload)
    # Sealing at SessionEnd was tempting and is wrong: SessionEnd is not guaranteed to run (a
    # crash or a kill skips it), so a ledger whose segments close only here would have its
    # boundaries decided by whether the process exited politely. Sealing stays an explicit
    # operator action via `stop-guessing ledger seal`.
    return _emit({
        "op": "session.close",
        "session_id": sid,
        "detail": json.dumps({"reason": payload.get("reason")}, sort_keys=True),
    })


HANDLERS = {
    "SessionStart": session_start,
    "UserPromptSubmit": prompt_submit,
    "PostToolUseFailure": tool_failed,
    "PreCompact": pre_compact,
    "SubagentStop": subagent_stop,
    "Stop": turn_stop,
    "SessionEnd": session_end,
}


def main(argv: list[str] | None = None) -> int:
    """Dispatch by event name. Never blocks, never fails a session."""
    argv = list(sys.argv[1:] if argv is None else argv)
    event = argv[0] if argv else os.environ.get("CLAUDE_HOOK_EVENT", "")

    raw = sys.stdin.buffer.read()
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except (json.JSONDecodeError, UnicodeDecodeError):
        return 0  # fail open on garbage, exactly as the gate does

    event = event or payload.get("hook_event_name") or ""
    handler = HANDLERS.get(event)
    if handler is None:
        return 0

    try:
        handler(payload)
    except Exception as exc:  # noqa: BLE001 - an observer must never break the session
        try:
            from stop_guessing.cli.hook_gate import _record_gap

            _record_gap(payload, exc)
        except Exception:  # noqa: BLE001
            print(f"STOP-GUESSING {event}: {exc}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
