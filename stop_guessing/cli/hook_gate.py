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
#:
#: #87: `check_credentials.sh` used to head this list and was never in the vendored tree, because it
#: is not part of `moonsoup/no-noodles` — it is an OPERATOR-installed hook. Superseding removed its
#: standalone registration while the dispatcher could not run it, so the operator's credential
#: hard-stop silently became a logged finding. It now lives in `OPERATOR_RULES` instead: not run
#: here, not superseded, and CHECKED for.
VENDORED_ORDER = (
    "no_noodle.sh",
    "check_before_build.sh",
    "risk_gate.sh",
)

#: Controls that belong to the operator, which this tool must never take over and never disable.
#:
#: The rule: a tool may only supersede a control it can actually execute. For everything else the
#: operator's own registration stays exactly where they put it — and the dispatcher VERIFIES it is
#: still wired up, which is strictly more than was checked before. Running the operator's hook from
#: here in addition would double-execute a blocking rule; confirming it is registered would not.
OPERATOR_RULES = ("check_credentials.sh",)


def vendored_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "compat" / "nonoodles"


def operator_rules_intact(settings: Path | None = None) -> list[str]:
    """Operator-owned controls that are no longer registered. Empty means all still wired.

    A missing entry here is not this tool's doing — but it IS this tool's business to notice, since
    superseding is the thing most likely to have caused it.
    """
    path = settings or (
        Path(os.environ.get("CLAUDE_CONFIG_DIR") or (Path.home() / ".claude")) / "settings.json")
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []          # no settings to check is not evidence of removal
    registered = json.dumps(data.get("hooks") or {})
    return [r for r in OPERATOR_RULES if r not in registered]


#: Per-hook wall-clock budget in the PRODUCTION path. The documented dispatcher budget is ~40 ms
#: p95, so 30 s is already 750x headroom and a vendored hook exceeding it is broken, not slow. It
#: stays short here on purpose: a long timeout in `PreToolUse` means one hung rule stalls every tool
#: call in the session.
VENDORED_TIMEOUT = 30

#: What a PROOF or a corpus replay uses instead. Those run many hooks back to back, often while a
#: test suite and a SHACL validator are competing for the same cores, and CLAIM-16/17 flapped on
#: exactly that — `no_noodle.sh` and `install.sh` timed out at 30 s under load and two claims went
#: UNPROVEN with nothing wrong. A verdict that depends on machine load is not a verdict. This is
#: headroom for measurement, not a relaxed assertion: the claim is that the vendored rules still run
#: and still produce identical output, and how long they take under contention is incidental to it.
VENDORED_TIMEOUT_BATCH = 300


def run_vendored(
    payload: bytes,
    hooks_dir: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int = VENDORED_TIMEOUT,
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
    missing: list[str] = []
    for name in VENDORED_ORDER:
        hook = d / name
        if not hook.is_file():
            # #71 (SG-HARD-038): this used to `continue` in silence, so deleting a vendored rule
            # made the dispatcher strictly more permissive with no signal anywhere. The whole
            # supersession claim is that these rules keep running; a missing one falsifies it.
            # It cannot fail closed — that would let a packaging slip block every tool call — so
            # it is recorded as a critical finding and surfaced.
            missing.append(name)
            continue
        res = subprocess.run(  # noqa: S603
            ["bash", str(hook)], input=payload, capture_output=True, timeout=timeout,
            env=env if env is not None else None,
        )
        if res.returncode != 0:
            return res.returncode, res.stdout.decode("utf-8", "replace"), name
    if missing:
        _record_missing_rules(missing, d)
    return None


def _record_missing_rules(missing: list[str], hooks_dir: Path) -> None:
    """A vendored rule that is not on disk is a critical configuration finding, not a no-op."""
    try:
        from stop_guessing.attest.keys import discover
        from stop_guessing.ledger.sink import record
        from stop_guessing.recorder.daemon import ledger_path

        cfg = Path(os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude"))
        got = discover(config_dir=cfg)
        record(ledger_path(cfg), {
            "op": "recorder.selfcheck",
            "actor": "stop-guessing/hook_gate",
            "severity": "critical",
            "at": _iso_now(),
            "detail": (f"{len(missing)} vendored rule(s) absent from {hooks_dir}: "
                       f"{', '.join(missing)}. The dispatcher is more permissive than the "
                       f"supersession claim states."),
            "known_gaps": [f"vendored rule missing: {n}" for n in missing],
            "alterations": [],
        }, got[0] if got else None)
    except Exception:  # noqa: BLE001 - never let recording a finding break the tool call
        print(f"STOP-GUESSING: vendored rule(s) missing and unrecordable: {', '.join(missing)}",
              file=sys.stderr)


def _iso_now() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _record_disabled_once() -> None:
    """Record that custody recording was switched off, exactly once per profile-day.

    Deliberately not once per call: a disabled session makes thousands of tool calls and a
    record per call would bury its own finding. A marker file bounds it without needing state
    the disabled path is meant to avoid touching.
    """
    try:
        cfg = Path(os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude"))
        from stop_guessing.paths import data_home

        stamp = data_home() / f"disabled-{_iso_now()[:10]}.marker"
        if stamp.exists():
            return
        stamp.parent.mkdir(parents=True, exist_ok=True)

        from stop_guessing.attest.keys import discover
        from stop_guessing.ledger.sink import record
        from stop_guessing.recorder.daemon import ledger_path

        got = discover(config_dir=cfg)
        record(ledger_path(cfg), {
            "op": "recorder.selfcheck",
            "actor": "stop-guessing/hook_gate",
            "severity": "critical",
            "at": _iso_now(),
            "detail": ("custody recording DISABLED via $STOP_GUESSING_DISABLE=1. Tool calls from "
                       "this point are not recorded. Absence of records after this entry means "
                       "recording was off, not that nothing happened."),
            "known_gaps": ["custody recording disabled by environment variable"],
            "alterations": [],
        }, got[0] if got else None)
        stamp.write_text(_iso_now(), encoding="utf-8")
    except Exception:  # noqa: BLE001 - the disable path must never break the tool call
        print("STOP-GUESSING: custody recording is DISABLED via $STOP_GUESSING_DISABLE",
              file=sys.stderr)


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


#: Strength order. A project may move RIGHT along this list, never left.
POSTURE_ORDER = ("observe", "steer", "bar")


def _managed_posture() -> str | None:
    """The floor an operator sets outside project write authority (#47).

    `managed.json` sits in the profile directory, not the project, so the recorded party cannot
    edit it as part of its ordinary work. Absent means no floor, which is the current default and
    keeps every existing installation behaving exactly as before.
    """
    import json as _json

    cfg = Path(os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude"))
    try:
        v = _json.loads((cfg / "managed.json").read_text(encoding="utf-8")).get("posture")
    except (OSError, ValueError):
        return None
    return v if v in POSTURE_ORDER else None


def _not_weaker_than(requested: str, floor: str | None) -> str:
    """Honour a request only where it does not loosen the managed floor."""
    if not floor:
        return requested
    return requested if POSTURE_ORDER.index(requested) >= POSTURE_ORDER.index(floor) else floor


#: The shipped default, named once so `doctor` and the docs cannot drift from the resolver.
DEFAULT_POSTURE = "observe"


def posture_source(cwd: str | None) -> tuple[str, str, str]:
    """``(effective_posture, human_description_of_who_set_it, the_path_to_change)``.

    `resolve_posture` answers *what* and discards *where from*, so a profile sitting in `steer`
    looked identical to one on the shipped default and the operator had no way to see the
    difference without reading the config chain by hand. Reporting is the whole job here: nothing
    in this function changes anything, because choosing the posture belongs to the operator.
    """
    import json as _json

    cfg = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude")
    effective = resolve_posture(cwd)
    managed = _managed_posture()

    layers = []
    if cwd:
        layers.append(("project config", Path(cwd) / ".stop-guessing.json"))
    layers.append(("profile config", Path(cfg) / "stop-guessing.json"))
    for label, path in layers:
        try:
            v = _json.loads(path.read_text(encoding="utf-8")).get("posture")
        except (OSError, ValueError):
            continue
        if v in ("observe", "steer", "bar"):
            if managed and v != effective:
                return effective, (f"managed policy ({Path(cfg) / 'managed.json'}), which "
                                   f"overrode {label} `{v}`"), str(Path(cfg) / "managed.json")
            return effective, f"{label}: {path}", str(path)

    legacy = Path(cfg) / "stop-guessing.state"
    try:
        if legacy.read_text(encoding="utf-8").strip() in ("observe", "steer", "bar"):
            return effective, f"legacy state file: {legacy}", str(legacy)
    except OSError:
        pass
    if managed:
        return effective, f"managed policy: {Path(cfg) / 'managed.json'}", str(
            Path(cfg) / "managed.json")
    return effective, "nothing — this is the shipped default", str(
        Path(cfg) / "stop-guessing.json")


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

    # #47 (SG-HARD-013). Project config took precedence over profile config with nothing above
    # it, so an agent with ordinary project write authority could drop a .stop-guessing.json
    # setting posture=observe and turn the enforcement it was subject to off — then, with the
    # ledger protection switched off the same way, modify the evidence. The recorded party must
    # not be able to weaken the policy it is recorded under.
    #
    # A MANAGED layer now sits above everything: `managed.json` in the profile, which lives
    # outside project write authority. Project config may still TIGHTEN (observe -> steer -> bar)
    # and is simply ignored where it would loosen. Nothing is removed — every existing layer keeps
    # working, and a project that wants more enforcement still gets it.
    managed = _managed_posture()

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
            return _not_weaker_than(v, managed)
    legacy = Path(cfg) / "stop-guessing.state"
    try:
        v = legacy.read_text(encoding="utf-8").strip()
        if v in ("observe", "steer", "bar"):
            return _not_weaker_than(v, managed)
    except OSError:
        pass
    return managed or DEFAULT_POSTURE


def _gap_frames(exc: BaseException, limit: int = 6) -> list[str]:
    """`file:line in function` for the last frames of a crash. Never source text.

    Enough to point at the defect, bounded so the ledger stays a record of what happened rather
    than a copy of the code it happened in.
    """
    import traceback

    try:
        return [f"{f.filename}:{f.lineno} in {f.name}"
                for f in traceback.extract_tb(exc.__traceback__)[-limit:]]
    except Exception:  # noqa: BLE001 - diagnosis must never be the thing that fails
        return []


def _gap_runtime() -> dict:
    """Which interpreter and which copy of the package actually ran.

    A crash that only reproduces under the harness and not when the same hook is run by hand is a
    question about resolution, not about logic, and this is what answers it.
    """
    import sys

    try:
        import stop_guessing

        return {"python": sys.executable,
                "package": getattr(stop_guessing, "__file__", None),
                "version": getattr(stop_guessing, "__version__", None),
                "cwd": os.getcwd()}
    except Exception:  # noqa: BLE001
        return {"python": sys.executable}


def _record_gap(payload: dict, exc: BaseException) -> None:
    """Append a critical selfcheck record so a crashed gate is visible, never silent."""
    try:
        # #61 (SG-HARD-024). This used from_env(), but a normal installation keeps its key in a
        # mode-600 keyfile that install.sh writes. Against a keyed ledger an unkeyed append is
        # REFUSED — so the one path whose entire job is to record that something went wrong was
        # itself failing, and the exception was swallowed. Gaps were silent precisely when they
        # mattered. Use the same discovery every other caller uses.
        from stop_guessing.attest.keys import discover
        from stop_guessing.ledger.sink import record

        # The KEY still comes from the profile — that is a credential, not data, and it is
        # deliberately not project-local: a key committed alongside a repo would be no key at all.
        got = discover(config_dir=os.environ.get("CLAUDE_CONFIG_DIR"))
        # Project-local: this used to write into the agent's shared profile dir.
        from stop_guessing.paths import ledger_file

        ledger = ledger_file()
        record(ledger, {
            "op": "recorder.selfcheck",
            "actor": "stop-guessing/hook_gate",
            "at": __import__("datetime").datetime.now(
                __import__("datetime").UTC).isoformat(timespec="milliseconds"),
            "severity": "critical",
            "detail": f"custody gate raised {type(exc).__name__}: {exc}",
            # WHERE it was raised, not just what. A critical record reading
            # "NameError: name '_content_binding' is not defined" and nothing else is very nearly
            # undiagnosable: it names a symbol without naming the file, the line, or the module the
            # running interpreter actually loaded — and when several copies of the package are
            # reachable (a checkout, an installed runtime, a venv), which copy raised it is the
            # whole question. This was found the hard way against 200-odd such records that could
            # not be traced to a file.
            #
            # Bounded on purpose: the last frames only, and paths as the interpreter resolved them,
            # so the record stays a diagnostic and does not become a transcript.
            "traceback": _gap_frames(exc),
            # Which copy of the package is executing. The same defect looks identical from a repo
            # checkout and a stale installed runtime, and telling them apart is what says whether
            # the fix is "edit the source" or "reinstall".
            "runtime": _gap_runtime(),
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
        # #83 (SG-HARD-050): this returned silently, so custody could be switched off for a whole
        # session with nothing in the ledger saying it had been. "No records" then reads as "no
        # activity" rather than "recording was disabled", which is the more dangerous of the two
        # and is indistinguishable after the fact. Record the transition on the way through — once
        # per session, so a disabled session leaves one clear marker rather than a flood.
        _record_disabled_once()
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
        # DELIBERATELY SILENT. This used to emit `permissionDecision: "allow"` under the comment
        # "`allow` with a reason is a warning; it does not interrupt" — which mistook the semantics.
        # In Claude Code an explicit `allow` from PreToolUse does not mean "no objection": it
        # AUTO-APPROVES the call and suppresses the permission prompt the host would otherwise
        # have raised.
        #
        # Under `bypassPermissions` that was merely redundant. Under `acceptEdits` it was a real
        # grant — that mode auto-accepts file edits but still prompts for Bash, so this turned a
        # would-be prompt into a silent approval, including on the ad-hoc `curl | python3` shape
        # that `no_noodle.sh` permits on its first occurrence in a project. A recorder was handing
        # out permission the operator's own settings would have asked about, which is precisely
        # what this tool is not for: it respects the permissions already set, and does not seek or
        # grant them.
        #
        # Emitting nothing is "this hook has no opinion", so the host's permission model runs
        # exactly as configured. Nothing is lost from the evidence: the decision, its reason and
        # the counterfactual ("would have asked, but permission_mode=… is a standing decision not
        # to be interrupted") are already in the custody record written by `decide()`.
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
