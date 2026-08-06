"""Driving the `hook:` surfaces, and the controls that stop it being a rubber stamp.

Six claims declared `hook:` surfaces that their procedures never went through — the procedure
called the underlying function directly, so the gate correctly said "registration is not
execution". The tempting fix was to withdraw the surfaces. That would have cleared the finding by
reducing what was claimed, which is the exact move `prove/scope.py` now catches, so the surfaces
stayed and the hooks get driven for real.

An exerciser that returns everything handed to it proves nothing — the sandbox self-test in this
repo already produced a false pass that way, by "blocking" every probe including the control. So
the load-bearing tests here are the negative ones: an unknown event, a crashing hook, and a hook
that writes unparseable stdout must all be EXCLUDED.
"""

from __future__ import annotations

import json
import subprocess
import sys

from stop_guessing.prove.procedures import HOOK_MODULES, HOOK_PAYLOADS, exercise_hooks
from stop_guessing.version import repo_root

INSTALLED_EVENTS = [
    "SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse",
    "PostToolUseFailure", "PreCompact", "SubagentStop", "Stop", "SessionEnd",
]


# ── it does what it says ─────────────────────────────────────────────────────


def test_every_installed_event_can_be_driven():
    surfaces = [f"hook:{e}" for e in INSTALLED_EVENTS]
    got = exercise_hooks(*surfaces)
    missing = sorted(set(surfaces) - set(got))
    assert not missing, f"these hooks did not execute cleanly as subprocesses: {missing}"


def test_a_payload_exists_for_every_event_the_installer_registers():
    """A hook with no payload is silently skipped, so a missing one must fail here instead."""
    missing = [e for e in INSTALLED_EVENTS if e not in HOOK_PAYLOADS]
    assert not missing, f"no exercise payload for installed event(s): {missing}"


def test_the_payloads_carry_the_fields_the_handlers_read():
    """An empty dict proves the process starts, not that the handler works."""
    for event, payload in HOOK_PAYLOADS.items():
        assert payload.get("session_id"), f"{event} payload has no session_id"
    assert HOOK_PAYLOADS["PostToolUseFailure"].get("error"), \
        "the failure payload must carry `error` — the field Claude Code actually sends"
    assert "tool_input" in HOOK_PAYLOADS["PreToolUse"]


# ── the controls ─────────────────────────────────────────────────────────────


def test_an_unknown_event_is_not_reported_as_exercised():
    assert exercise_hooks("hook:NotARealEvent") == []


def test_a_crashing_hook_is_not_reported_as_exercised(monkeypatch):
    """The control that matters: if the hook would die in a real session, it did not run."""
    monkeypatch.setitem(HOOK_MODULES, "PreCompact", ("stop_guessing.cli.does_not_exist", []))
    assert exercise_hooks("hook:PreCompact") == [], \
        "a hook whose module cannot even be imported was counted as exercised"


def test_a_hook_emitting_unparseable_stdout_is_not_exercised(tmp_path, monkeypatch):
    mod = tmp_path / "sg_broken_hook.py"
    mod.write_text("import sys\nsys.stdin.read()\nprint('not json at all')\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.setenv("PYTHONPATH", f"{tmp_path}:{repo_root()}")
    monkeypatch.setitem(HOOK_MODULES, "Stop", ("sg_broken_hook", []))
    assert exercise_hooks("hook:Stop") == []


def test_exercising_writes_nothing_into_the_real_ledger():
    """A ledger containing its own test fixtures is not evidence."""
    from stop_guessing.prove import runner

    before = runner.DEFAULT_LEDGER.read_bytes() if runner.DEFAULT_LEDGER.exists() else b""
    exercise_hooks(*(f"hook:{e}" for e in INSTALLED_EVENTS))
    after = runner.DEFAULT_LEDGER.read_bytes() if runner.DEFAULT_LEDGER.exists() else b""
    assert before == after, "exercising hooks mutated the evidence ledger"


# ── it must match what is actually deployed ──────────────────────────────────


def test_the_exercised_module_is_the_module_the_installer_registers():
    """If install.sh and the exerciser drift, the proof covers code nobody runs."""
    installer = (repo_root() / "install.sh").read_text(encoding="utf-8")
    for event in INSTALLED_EVENTS:
        mod, extra = HOOK_MODULES.get(event, ("stop_guessing.cli.hook_lifecycle", [event]))
        short = mod.rsplit(".", 1)[-1]
        assert short in installer, f"{event} is exercised via {mod}, which install.sh never writes"
        if extra:
            assert f"hook_lifecycle {event}" in installer, \
                f"install.sh does not register {event} on hook_lifecycle"


def test_a_hook_run_with_a_real_payload_emits_a_parseable_response():
    """End to end through the entry point, asserted rather than assumed."""
    body = dict(HOOK_PAYLOADS["PreToolUse"], hook_event_name="PreToolUse")
    res = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "stop_guessing.cli.hook_gate"],
        input=json.dumps(body).encode("utf-8"),
        capture_output=True, cwd=str(repo_root()), timeout=120,
    )
    assert res.returncode in (0, 2), res.stderr.decode()[-500:]
    out = res.stdout.decode().strip()
    if out:
        parsed = json.loads(out)
        assert isinstance(parsed, dict)


# ── it must never hang the release gate ──────────────────────────────────────


def test_the_exercisers_never_inherit_stdin():
    """A `prove` run that blocks forever on stdin has failed open in the worst possible way.

    Observed: `prove` ran for ten minutes with 14 seconds of CPU, sleeping, having produced no
    verdict — in a background task with no terminal. A gate that never returns is worse than one
    that returns a finding, because nothing surfaces at all.
    """
    import re

    src = (repo_root() / "stop_guessing/prove/procedures.py").read_text(encoding="utf-8")
    body = src[src.index("def exercise_cli("):]
    body = body[:body.index("\n@proof(")] if "\n@proof(" in body else body
    src_hooks = src[src.index("def exercise_hooks("):]
    src_hooks = src_hooks[:src_hooks.index("\ndef ")] if "\ndef " in src_hooks else src_hooks

    assert "stdin=subprocess.DEVNULL" in body, \
        "exercise_cli inherits the caller's stdin; a surface that reads it will hang the gate"
    # exercise_hooks passes input=, which supplies and then closes stdin — equally safe.
    assert re.search(r"input=json\.dumps", src_hooks), \
        "exercise_hooks must supply stdin explicitly rather than inherit it"


def test_a_hanging_surface_is_bounded_and_not_counted(tmp_path, monkeypatch):
    """The control for the timeout path: it must give up AND not report the surface as run."""
    mod = tmp_path / "sg_hanging_hook.py"
    mod.write_text("import time\ntime.sleep(600)\n", encoding="utf-8")
    monkeypatch.setenv("PYTHONPATH", f"{tmp_path}:{repo_root()}")
    monkeypatch.setitem(HOOK_MODULES, "Stop", ("sg_hanging_hook", []))
    assert exercise_hooks("hook:Stop", timeout=3) == [], \
        "a hook that never returns was counted as exercised"


def test_the_default_timeout_is_bounded():
    import inspect

    from stop_guessing.prove.procedures import exercise_cli

    for fn in (exercise_cli, exercise_hooks):
        default = inspect.signature(fn).parameters["timeout"].default
        # Bounded is the requirement, not short: a 120s cap silently cut `compat verify`, which
        # legitimately takes ~430s replaying the corpus, and two claims went UNPROVEN for it.
        assert 0 < default <= 900, f"{fn.__name__} has an unbounded default timeout: {default}"
