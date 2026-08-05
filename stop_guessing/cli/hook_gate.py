"""The single PreToolUse entry that replaces four.

Order is not an implementation detail — it is the compatibility contract. The vendored no-noodles
rules run first, in their **original registration order**, and the first non-zero exit wins and
stops. Its stdout is passed through byte-for-byte as the `permissionDecisionReason`, so a user who
has learned what `NO-NOODLE:` looks like sees exactly the same text after supersession.

Only if every vendored rule allows does the custody gate get a say. That ordering means
supersession can never make something *more* permissive than no-noodles was: the union of
refusals is preserved by construction.

Two behaviours inherited deliberately:

- **Fail open on garbage.** Unparseable stdin exits 0. A gate that blocks on malformed input
  becomes a denial of service against the whole session.
- **Observation never blocks.** `risk_observe` runs regardless and can never be the reason a call
  is refused.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

#: Original registration order from ~/.claude/settings.json. Do not reorder.
VENDORED_ORDER = (
    "check_credentials.sh",
    "no_noodle.sh",
    "check_before_build.sh",
    "risk_gate.sh",
)


def vendored_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "compat" / "nonoodles"


def run_vendored(
    payload: bytes,
    hooks_dir: Path | None = None,
    env: dict[str, str] | None = None,
) -> tuple[int, str, str] | None:
    """Run the vendored rules in order. Returns the first refusal, or None if all allow.

    ``env`` is explicit rather than always inherited. In production the session env is correct —
    the hooks must see the real `CLAUDE_CONFIG_DIR`. In a test or a proof it must NOT be, because
    `no_noodle.sh` keeps per-(shape, project) counters on disk: inheriting the caller's env makes
    the result depend on unrelated prior activity. That is the exact flaw no-noodles' own tests
    carried until it was found (`tests/test_no_noodle.sh:38-40`), and it was reproduced here by
    CLAIM-17's proof failing.
    """
    d = hooks_dir or vendored_dir()
    for name in VENDORED_ORDER:
        hook = d / name
        if not hook.is_file():
            continue
        res = subprocess.run(  # noqa: S603
            ["bash", str(hook)], input=payload, capture_output=True, timeout=30,
            env=env if env is not None else None,
        )
        if res.returncode != 0:
            return res.returncode, res.stdout.decode("utf-8", "replace"), name
    return None


def emit_deny(reason: str) -> None:
    """The structured channel no existing hook in this estate uses."""
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }}))


def emit_ask(reason: str) -> None:
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "ask",
        "permissionDecisionReason": reason,
    }}))


def resolve_posture(cwd: str | None) -> str:
    """Resolve the posture through the four-layer chain. **The default is `observe`.**

    This tool exists to record chain of custody and data provenance as evidence. It is not a
    permission system and must not behave like one: the host already has a permission model, the
    operator has already configured it, and a second gate asking again is a tool overriding a
    decision its user has already made.

    So `observe` is the default — record everything, block nothing. `steer` and `bar` remain
    available and unchanged for anyone who wants enforcement, but they are opt-in.

    Order matches no-noodles' `resolve_state`: project, global, legacy, default.
    """
    import json as _json

    candidates = []
    if cwd:
        candidates.append(Path(cwd) / ".stop-guessing.json")
    cfg = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude")
    candidates.append(Path(cfg) / "stop-guessing.json")
    for c in candidates:
        try:
            v = _json.loads(c.read_text(encoding="utf-8")).get("posture")
        except (OSError, ValueError):
            continue
        if v in ("observe", "steer", "bar"):
            return v
    legacy = Path(cfg) / "stop-guessing.state"
    try:
        v = legacy.read_text(encoding="utf-8").strip()
        if v in ("observe", "steer", "bar"):
            return v
    except OSError:
        pass
    return "observe"


def _record_gap(payload: dict, exc: BaseException) -> None:
    """Append a critical selfcheck record so a crashed gate is visible, never silent."""
    try:
        from stop_guessing.attest.keys import from_env
        from stop_guessing.ledger.sink import record

        got = from_env()
        cfg = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude")
        ledger = Path(cfg) / "stop-guessing" / "ledger" / "custody.jsonl"
        record(ledger, {
            "op": "recorder.selfcheck",
            "actor": "stop-guessing/hook_gate",
            "at": __import__("datetime").datetime.now(
                __import__("datetime").UTC).isoformat(timespec="milliseconds"),
            "severity": "critical",
            "detail": f"custody gate raised {type(exc).__name__}: {exc}",
            "session_id": payload.get("session_id"),
            "tool": payload.get("tool_name"),
            "enforcement": "failed open — this call was NOT evaluated",
        }, got[0] if got else None)
    except Exception:  # noqa: BLE001 - recording a gap must never itself take the session down
        pass


def main(argv: list[str] | None = None) -> int:
    raw = sys.stdin.buffer.read()
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return 0  # fail open on garbage — no-noodles' rule, and the right one

    refusal = run_vendored(raw)
    if refusal is not None:
        _, stdout, hook = refusal
        # Byte-for-byte passthrough: the user sees the message they already know.
        emit_deny(stdout.rstrip("\n"))
        return 0

    if os.environ.get("STOP_GUESSING_DISABLE") == "1":
        return 0

    try:
        from stop_guessing.cli.gate import decide

        decision = decide(payload, posture=resolve_posture(payload.get("cwd")))
    except Exception as exc:  # noqa: BLE001
        # A gate that crashes must not take the session with it — but the gap must be RECORDED.
        # Fixes #23: this branch used to return 0 under a comment claiming it recorded a gap,
        # which is precisely the false assurance this project exists to catch.
        _record_gap(payload, exc)
        return 0

    if decision is None:
        return 0
    if decision["outcome"] == "deny":
        emit_deny(decision["reason"])
    elif decision["outcome"] == "ask":
        emit_ask(decision["reason"])
    elif decision.get("warning"):
        # Allowed, but the operator should see why it would otherwise have asked. `allow` with a
        # reason is a warning; it does not interrupt.
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "permissionDecisionReason": decision["reason"],
        }}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
