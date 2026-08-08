"""The default posture must never seek permission — the operator's constraint, as a test.

Recorded from the outset: *"you must respect the permissions that are already set. This is not
meant to block anything or seek permissions. It is for logging Chain of Custody and data provenance
to show evidence."*

`observe` is the default and this is what makes that promise mechanical. The one documented
exception is a write to the ledger itself, refused under every posture — that protects the evidence
rather than policing the operator, and `{"protect_ledger": false}` turns even that off.

`steer` and `bar` are opt-in and DO ask; that is their documented purpose and this file does not
touch them. The point is that nobody arrives at an asking gate by installing the tool.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from stop_guessing.version import repo_root

CLI = [sys.executable, "-m", "stop_guessing.cli.hook_gate"]

CASES = [
    ("a classified read", {"tool_name": "Read",
                           "tool_input": {"file_path": "/example/work/CSA/roster.csv"}}),
    ("an ordinary read", {"tool_name": "Read", "tool_input": {"file_path": "/etc/hosts"}}),
    ("a benign bash", {"tool_name": "Bash", "tool_input": {"command": "ls -la"}}),
    ("an egress", {"tool_name": "Bash",
                   "tool_input": {"command": "scp ./x.csv user@host:/tmp/"}}),
    ("a write", {"tool_name": "Write",
                 "tool_input": {"file_path": "/tmp/sg-observe/out.txt", "content": "x"}}),
]


def _run(body, cwd):
    env = dict(os.environ)
    env["CLAUDE_CONFIG_DIR"] = cwd            # hermetic: no profile config, so the DEFAULT applies
    return subprocess.run(  # noqa: S603
        CLI, input=json.dumps(body).encode("utf-8"),
        capture_output=True, cwd=str(repo_root()), timeout=300, env=env)


def _decision(out: str):
    out = out.strip()
    if not out:
        return None
    try:
        hso = (json.loads(out).get("hookSpecificOutput") or {})
    except ValueError:
        return None
    return hso.get("permissionDecision")


def test_the_shipped_default_posture_is_observe(tmp_path):
    """If this ever flips, everything below becomes a test of something else."""
    from stop_guessing.cli.hook_gate import resolve_posture

    os.environ["CLAUDE_CONFIG_DIR"] = str(tmp_path)
    try:
        assert resolve_posture(str(tmp_path)) == "observe"
    finally:
        os.environ.pop("CLAUDE_CONFIG_DIR", None)


def test_observe_never_asks_and_never_denies_ordinary_work(tmp_path):
    """Installing the tool must not put a second permission gate in front of the operator."""
    offenders = []
    for name, body in CASES:
        payload = {"session_id": "sg-observe", "hook_event_name": "PreToolUse",
                   "tool_use_id": "toolu_obs", "cwd": str(tmp_path), **body}
        d = _decision(_run(payload, str(tmp_path)).stdout.decode())
        if d in ("ask", "deny"):
            offenders.append((name, d))
    assert not offenders, (
        f"the DEFAULT posture interrupted the operator: {offenders}. observe records and blocks "
        "nothing; a recorder that prompts is overriding the decision its user already made.")


def test_observe_never_grants_either(tmp_path):
    """The other half. Recording is not deciding, in either direction."""
    for name, body in CASES:
        payload = {"session_id": "sg-observe", "hook_event_name": "PreToolUse",
                   "tool_use_id": "toolu_obs", "permission_mode": "acceptEdits",
                   "cwd": str(tmp_path), **body}
        assert _decision(_run(payload, str(tmp_path)).stdout.decode()) != "allow", (
            f"{name}: the default posture auto-approved a call")


def test_the_ledger_is_still_protected_under_observe(tmp_path):
    """The documented exception, and the control: 'never blocks' must not mean 'never protects'.

    Without this, `test_observe_never_asks…` would be satisfied by a gate that has no opinions at
    all, which is indistinguishable from a broken one.
    """
    ledger = tmp_path / "stop-guessing" / "ledger" / "custody.jsonl"
    ledger.parent.mkdir(parents=True, exist_ok=True)
    payload = {"session_id": "sg-observe", "hook_event_name": "PreToolUse",
               "tool_use_id": "toolu_obs", "cwd": str(tmp_path),
               "tool_name": "Write",
               "tool_input": {"file_path": str(ledger), "content": "forged"}}
    assert _decision(_run(payload, str(tmp_path)).stdout.decode()) == "deny", (
        "a write to the evidence ledger was not refused under observe — the one thing that must be")


#: Every surface that STATES the default in prose or in machine-readable policy, and must therefore
#: agree with `DEFAULT_POSTURE`. Paths are repo-relative.
#:
#: `IMPLEMENTATION_PLAN.md` and `CHANGELOG.md` are deliberately absent: they are historical-record
#: files (`depersonalise_paths.SKIP`) that state what WAS decided, and pinning them to the current
#: value would require falsifying the record to make a test pass. `docs/index.html` is generated, so
#: the generator `cmd_page.py` is what is pinned — the page itself is covered by `page check`.
DEFAULT_POSTURE_SURFACES = (
    ".claude-plugin/plugins/stop-guessing/commands/custody-options.md",
    ".agents/plugins/stop-guessing/.codex-plugin/plugin.json",
    "stop_guessing/cli/cmd_page.py",
    "README.md",
)


def _lines_asserting_a_stale_default(text: str, stale: tuple[str, ...]) -> list[str]:
    """Line numbers and text for every line that ASSERTS a default other than the shipped one.

    Split out from the scan so the matcher itself can be tested against the real drifted lines. A
    detector that has only ever been run against a clean tree is not known to detect anything.
    """
    hits = []
    for line_no, line in enumerate(text.splitlines(), 1):
        low = line.lower()
        # Only lines that actually ASSERT a default, so prose describing what `steer` does — or
        # recording that the default moved away from it — is not a false positive.
        if not ("default" in low and any(f"`{p}`" in low or f'"{p}"' in low
                                        or f"<code>{p}</code>" in low for p in stale)):
            continue
        if "moved from" in low or "superseded" in low or "used to" in low:
            continue
        hits.append(f"{line_no}: {line.strip()}")
    return hits


#: The exact lines this test was written for, as they stood before the fix. Verbatim, so the matcher
#: is proven against the real defect and not a paraphrase of it.
HISTORICAL_DRIFT = (
    "Three postures ship. Default is `steer`.",
    '    "posture_default": "steer",',
    "<p>Three postures ship; the default is <code>steer</code>. Full-depth tracking is the default "
    "and",
)

#: Lines that mention a non-default posture legitimately and must NOT be flagged.
MUST_NOT_FLAG = (
    "| `steer` | Asks on first touch of a classified artifact; denies on accumulation or egress. |",
    "The default moved from `steer` to `observe` deliberately.",
    "Full-depth tracking is the default and is never silently reduced.",
    "stop-guessing demo --posture steer   # the whole behaviour, every step citing its record id",
)


def test_the_drift_matcher_catches_the_drift_it_was_written_for():
    """Guards against the detector being quietly defanged into a test that cannot fail."""
    from stop_guessing.cli.hook_gate import DEFAULT_POSTURE, POSTURE_ORDER

    stale = tuple(p for p in POSTURE_ORDER if p != DEFAULT_POSTURE)
    for line in HISTORICAL_DRIFT:
        assert _lines_asserting_a_stale_default(line, stale), (
            f"the matcher no longer catches a line it was written to catch: {line!r}")
    for line in MUST_NOT_FLAG:
        assert not _lines_asserting_a_stale_default(line, stale), (
            f"the matcher flags a legitimate mention of a non-default posture: {line!r}")


def test_no_shipped_surface_names_a_different_default():
    """The default was changed in code and four surfaces went on advertising the old one.

    The operator hit this directly: the default moved to `observe`, but `/custody-options` still
    read "Default is `steer`", the published page said the same, and the Codex plugin manifest
    still declared `posture_default: steer` as machine-readable policy. Someone reading the docs to
    find out why they were still being asked for approval was told the asking posture was normal.

    `DEFAULT_POSTURE` exists so that "the docs cannot drift from the resolver" (hook_gate.py:237).
    That was an intention with nothing enforcing it. This enforces it.
    """
    from stop_guessing.cli.hook_gate import DEFAULT_POSTURE, POSTURE_ORDER

    stale = tuple(p for p in POSTURE_ORDER if p != DEFAULT_POSTURE)
    offenders = []
    for rel in DEFAULT_POSTURE_SURFACES:
        text = (repo_root() / rel).read_text(encoding="utf-8")
        offenders += [f"{rel}:{hit}" for hit in _lines_asserting_a_stale_default(text, stale)]
    assert not offenders, (
        f"the shipped default is `{DEFAULT_POSTURE}`, but these surfaces advertise another:\n"
        + "\n".join(offenders))


def test_the_documented_default_is_stated_where_operators_look():
    """Silence is the other failure mode: drift fixed by deleting the sentence teaches nobody.

    The two surfaces an operator actually reads to answer "why is it asking me?" must say what the
    default IS, not merely avoid saying the wrong thing.
    """
    from stop_guessing.cli.hook_gate import DEFAULT_POSTURE

    for rel in (".claude-plugin/plugins/stop-guessing/commands/custody-options.md", "README.md"):
        text = (repo_root() / rel).read_text(encoding="utf-8").lower()
        assert f"default is `{DEFAULT_POSTURE}`" in text, (
            f"{rel} never states that the default is `{DEFAULT_POSTURE}`")
