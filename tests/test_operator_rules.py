"""#87 — a tool may only supersede a control it can actually run.

`check_credentials.sh` headed `VENDORED_ORDER` and was never in the vendored tree: it is an
OPERATOR-installed hook, not part of `moonsoup/no-noodles`, so it was never ours to vendor.
`install.sh --supersede-no-noodles` removed its PreToolUse registration anyway, and the dispatcher
could not execute it — so the operator's credential hard-stop silently degraded to a logged
finding. That is the one rule their global instructions mark "Hard stop — enforced by hook".

The fix is not to vendor their hook into a public distribution. It is to stop taking over a control
this tool cannot run, and to CHECK the operator's registration is still there — which is strictly
more than was verified before.
"""

from __future__ import annotations

import json

from stop_guessing.cli.hook_gate import (
    OPERATOR_RULES,
    VENDORED_ORDER,
    operator_rules_intact,
    vendored_dir,
)
from stop_guessing.version import repo_root


def test_the_credential_hook_is_not_claimed_as_vendored():
    assert "check_credentials.sh" not in VENDORED_ORDER, (
        "the dispatcher claims to run a hook that has never existed in the vendored tree")
    assert "check_credentials.sh" in OPERATOR_RULES


def test_every_rule_the_dispatcher_runs_is_actually_present():
    """The general form of the bug: a declared rule that is not on disk."""
    missing = [n for n in VENDORED_ORDER if not (vendored_dir() / n).is_file()]
    assert not missing, f"VENDORED_ORDER names rules that are not vendored: {missing}"


def test_the_installer_does_not_supersede_an_operator_rule():
    body = (repo_root() / "install.sh").read_text(encoding="utf-8")
    line = next(ln for ln in body.splitlines() if ln.startswith("SUPERSEDED = "))
    for rule in OPERATOR_RULES:
        assert rule not in line, (
            f"install.sh removes the registration for {rule}, which the dispatcher cannot run")


def test_a_removed_operator_registration_is_detected(tmp_path):
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"hooks": {"PreToolUse": [{"hooks": [
        {"command": "bash /x/hooks/coc_gate.sh"}]}]}}), encoding="utf-8")
    assert operator_rules_intact(settings) == ["check_credentials.sh"]


def test_an_intact_operator_registration_is_not_a_finding(tmp_path):
    """The control: a checker that always reports a finding is not a checker."""
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"hooks": {"PreToolUse": [{"hooks": [
        {"command": "bash /x/hooks/check_credentials.sh"},
        {"command": "bash /x/hooks/coc_gate.sh"}]}]}}), encoding="utf-8")
    assert operator_rules_intact(settings) == []


def test_absent_settings_is_not_treated_as_removal(tmp_path):
    """No settings file is 'nothing to check', not 'the control was deleted'."""
    assert operator_rules_intact(tmp_path / "nope.json") == []


def test_the_live_profiles_still_have_their_credential_hook():
    """The real system, not a fixture. This is the state the operator is actually running in."""
    import os
    from pathlib import Path

    checked = 0
    for profile in sorted(Path.home().glob(".claude*")):
        settings = profile / "settings.json"
        if not settings.is_file():
            continue
        checked += 1
        gone = operator_rules_intact(settings)
        assert not gone, f"{profile.name} has lost its credential hard-stop: {gone}"
    assert checked, "no live profile was checked"
    assert os.environ is not None


def test_the_restored_credential_hook_actually_blocks(tmp_path):
    """A registration is not a control. Drive the operator's hook and confirm it refuses.

    Registering a hook and asserting the registration is exactly the mistake that let this defect
    live: `check_credentials.sh` was present on disk and expected by name for weeks while never
    executing. So this feeds it a real payload and checks the exit code.

    The payload names no real credential — it is the SHAPE of the command that is blocked.
    """
    import json as _json
    import subprocess
    from pathlib import Path as _P

    hook = _P.home() / ".claude-ies" / "hooks" / "check_credentials.sh"
    if not hook.is_file():
        import pytest
        pytest.skip("no credential hook installed in this profile")

    blocked = _json.dumps({"tool_name": "Bash",
                           "tool_input": {"command": "env | grep TOKEN"}}).encode()
    res = subprocess.run(["bash", str(hook)], input=blocked,  # noqa: S603
                         capture_output=True, timeout=60)
    assert res.returncode == 2, (
        f"the credential hard-stop did not block an env-dump shape (exit {res.returncode})")

    # The control: an ordinary command must pass, or "it blocks" is satisfied by blocking
    # everything, which would be indistinguishable from a broken hook.
    ok = _json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls -la"}}).encode()
    res2 = subprocess.run(["bash", str(hook)], input=ok,  # noqa: S603
                          capture_output=True, timeout=60)
    assert res2.returncode == 0, "the credential hook blocks ordinary commands too"
