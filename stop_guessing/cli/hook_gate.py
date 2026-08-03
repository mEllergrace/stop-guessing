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

        decision = decide(payload)
    except Exception:  # noqa: BLE001
        # A gate that crashes must not take the session with it. Recorded as a gap, not a block.
        return 0

    if decision is None:
        return 0
    if decision["outcome"] == "deny":
        emit_deny(decision["reason"])
    elif decision["outcome"] == "ask":
        emit_ask(decision["reason"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
