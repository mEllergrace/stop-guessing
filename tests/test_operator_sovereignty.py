"""The class of defect this project keeps producing: the tool overriding operator-owned state.

Two instances were found by the operator rather than by this suite:

  #87  `--supersede-no-noodles` removed the registration for `check_credentials.sh`, an
       operator-installed hook the dispatcher could not execute, silently disabling their
       credential hard-stop.
  #88  the gate emitted `permissionDecision: "allow"`, which auto-approves a call and suppresses
       the host's prompt — a recorder handing out permission.

Both were closed individually. Neither closed the CLASS, and "I'd treat that as the open risk" is
not a control. This file enumerates every way the tool can touch state it does not own and asserts
each one is either impossible or explicitly preserving.

The governing rule, from the operator's own constraint:

    it respects the permissions and configuration already set,
    it neither seeks nor grants them,
    and it leaves nothing behind in a directory it does not own.

Two further instances were found by writing this file, which is the point of writing it:
install.sh clobbered an operator-edited copy of the vendored slash-command docs, and --uninstall
left seven lifecycle hook scripts on disk while removing their registrations.
"""

from __future__ import annotations

import json
import os
import re
import subprocess

import pytest

from stop_guessing.version import repo_root

REPO = repo_root()
INSTALL = REPO / "install.sh"


@pytest.fixture
def stub_bin(tmp_path):
    """A PATH stub so the installer's optional steps do not touch the real machine."""
    d = tmp_path / "bin"
    d.mkdir()
    for name in ("launchctl", "sudo", "dscl", "security"):
        p = d / name
        p.write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
        p.chmod(0o755)
    return d


def _profile(tmp_path, extra_hooks=None, extra_settings=None):
    prof = tmp_path / "claude"
    for sub in ("hooks", "commands", "skills"):
        (prof / sub).mkdir(parents=True, exist_ok=True)
    settings = {"model": "opus", "hooks": {"PreToolUse": [{"hooks": list(extra_hooks or [])}]}}
    settings.update(extra_settings or {})
    (prof / "settings.json").write_text(json.dumps(settings), encoding="utf-8")
    return prof


def _install(prof, stub_bin, *args):
    env = dict(os.environ)
    env["PATH"] = f"{stub_bin}:{env['PATH']}"
    return subprocess.run(["bash", str(INSTALL), "--profile", str(prof), *args],  # noqa: S603
                          capture_output=True, text=True, timeout=1800, env=env, cwd=str(REPO))


def _pre_hooks(prof):
    d = json.loads((prof / "settings.json").read_text(encoding="utf-8"))
    return [h.get("command", "") for g in d.get("hooks", {}).get("PreToolUse", [])
            for h in g.get("hooks", [])]


# ── it may only supersede a control it can execute (#87, generalised) ────────


def test_nothing_is_superseded_that_the_dispatcher_cannot_run():
    """The general form. A name on the supersede list with no runnable rule behind it disables it."""
    from stop_guessing.cli.hook_gate import VENDORED_ORDER, vendored_dir

    line = next(ln for ln in INSTALL.read_text(encoding="utf-8").splitlines()
                if ln.startswith("SUPERSEDED = "))
    names = re.findall(r'"([^"]+)"', line)
    assert names, "could not parse SUPERSEDED"
    for name in names:
        assert name in VENDORED_ORDER, (
            f"install.sh removes the registration for {name}, which the dispatcher does not run")
        assert (vendored_dir() / name).is_file(), (
            f"{name} is superseded and listed in VENDORED_ORDER but is not on disk")


# ── it may not overwrite what the operator has edited ────────────────────────


def test_an_operator_edited_vendored_doc_is_not_clobbered(tmp_path, stub_bin):
    """check_before_build.sh carried 63 lines of local hardening that upstream's installer
    silently reverted. Our installer must not repeat that with the docs it ships."""
    prof = _profile(tmp_path)
    edited = prof / "commands" / "no-noodle.md"
    edited.write_text("# MY LOCAL EDIT — do not lose this\n", encoding="utf-8")

    res = _install(prof, stub_bin)
    assert res.returncode == 0, (res.stdout + res.stderr)[-1000:]
    assert "MY LOCAL EDIT" in edited.read_text(encoding="utf-8"), (
        "install.sh overwrote an operator-modified copy of a vendored doc")
    assert "PRESERVED" in res.stdout, "the preservation was silent; it must be reported"


def test_an_absent_or_identical_doc_is_still_installed(tmp_path, stub_bin):
    """The control: 'never clobber' must not become 'never install'."""
    prof = _profile(tmp_path)
    res = _install(prof, stub_bin)
    assert res.returncode == 0
    for doc in ("no-noodle", "noodle-options", "custody", "custody-options"):
        assert (prof / "commands" / f"{doc}.md").is_file(), f"/{doc} was not installed"


def test_unrelated_hooks_and_settings_survive_installation(tmp_path, stub_bin):
    prof = _profile(
        tmp_path,
        extra_hooks=[{"type": "command", "command": "bash /somewhere/operator_own_hook.sh"}],
        extra_settings={"statusLine": {"type": "command", "command": "mine"}},
    )
    res = _install(prof, stub_bin)
    assert res.returncode == 0
    data = json.loads((prof / "settings.json").read_text(encoding="utf-8"))
    assert data["model"] == "opus"
    assert data["statusLine"] == {"type": "command", "command": "mine"}
    assert any("operator_own_hook.sh" in c for c in _pre_hooks(prof)), (
        "an unrelated PreToolUse hook was removed by our installer")


# ── it must leave nothing behind in a directory it does not own ──────────────


def test_uninstall_removes_every_script_it_installed(tmp_path, stub_bin):
    """--uninstall removed two scripts and left seven lifecycle ones on disk."""
    prof = _profile(tmp_path)
    assert _install(prof, stub_bin).returncode == 0
    ours = sorted(p.name for p in (prof / "hooks").glob("coc_*.sh"))
    assert len(ours) >= 9, f"expected the full hook set to be installed, got {ours}"

    res = _install(prof, stub_bin, "--uninstall")
    assert res.returncode == 0, (res.stdout + res.stderr)[-800:]
    left = sorted(p.name for p in (prof / "hooks").glob("coc_*.sh"))
    assert left == [], f"--uninstall left our executables in the operator's hooks dir: {left}"


def test_uninstall_removes_every_registration_it_added(tmp_path, stub_bin):
    prof = _profile(tmp_path)
    _install(prof, stub_bin)
    _install(prof, stub_bin, "--uninstall")
    data = json.loads((prof / "settings.json").read_text(encoding="utf-8"))
    blob = json.dumps(data.get("hooks") or {})
    assert "coc_" not in blob, f"--uninstall left our registrations behind: {blob[:300]}"


def test_uninstall_preserves_the_operators_own_hook(tmp_path, stub_bin):
    prof = _profile(
        tmp_path, extra_hooks=[{"type": "command", "command": "bash /x/operator_own_hook.sh"}])
    _install(prof, stub_bin)
    _install(prof, stub_bin, "--uninstall")
    assert any("operator_own_hook.sh" in c for c in _pre_hooks(prof)), (
        "--uninstall removed a hook we never installed")


def test_uninstall_preserves_the_accumulated_evidence(tmp_path, stub_bin):
    """Destroying the ability to check evidence is not an uninstall."""
    prof = _profile(tmp_path)
    _install(prof, stub_bin)
    ledger = prof / "stop-guessing" / "ledger"
    ledger.mkdir(parents=True, exist_ok=True)
    (ledger / "custody.jsonl").write_text('{"seq":0}\n', encoding="utf-8")
    obs = prof / "observations.jsonl"
    obs.write_text('{"shape":"x"}\n', encoding="utf-8")

    _install(prof, stub_bin, "--uninstall")
    assert (ledger / "custody.jsonl").is_file(), "--uninstall destroyed the audit trail"
    assert obs.is_file(), "--uninstall removed no-noodles' observation data"


# ── it may not decide on the operator's behalf ───────────────────────────────


def test_the_gate_has_no_grant_channel():
    """#88, kept in the class suite rather than only in its own file."""
    src = (REPO / "stop_guessing/cli/hook_gate.py").read_text(encoding="utf-8")
    code = "\n".join(ln for ln in src.splitlines() if not ln.lstrip().startswith("#"))
    assert '"permissionDecision": "allow"' not in code


def test_only_the_gate_speaks_to_the_host_at_all():
    """PostToolUse and the lifecycle hooks must not rewrite output or inject context.

    A recorder that edits what the model sees is not recording, and `updatedToolOutput` /
    `additionalContext` are the two channels that would let it.
    """
    for mod in ("hook_post.py", "hook_lifecycle.py"):
        src = (REPO / "stop_guessing" / "cli" / mod).read_text(encoding="utf-8")
        code = "\n".join(ln for ln in src.splitlines() if not ln.lstrip().startswith("#"))
        for channel in ("updatedToolOutput", "updatedInput", "additionalContext",
                        "hookSpecificOutput"):
            assert channel not in code, f"{mod} writes to the host via {channel}"


def test_no_code_path_writes_an_operator_posture_config():
    """The tool must never choose the operator's posture for them.

    Two proof procedures write `{"posture": "steer"}`; both must be inside a temporary directory.
    A profile whose posture was set by the tool is a tool that decided how much it may interrupt.
    """
    src = (REPO / "stop_guessing/prove/procedures.py").read_text(encoding="utf-8")
    for m in re.finditer(r'.*stop-guessing\.json.*write_text.*', src):
        line = m.group(0)
        window = src[max(0, m.start() - 2500):m.start()]
        assert "tempfile" in window or "mkdtemp" in window or "TemporaryDirectory" in window, (
            f"a posture config is written outside a temporary directory: {line.strip()}")

    for mod in ("stop_guessing/cli/hook_gate.py", "stop_guessing/cli/gate.py"):
        code = (REPO / mod).read_text(encoding="utf-8")
        assert 'stop-guessing.json").write_text' not in code, f"{mod} writes a posture config"
    assert "posture" not in INSTALL.read_text(encoding="utf-8"), (
        "install.sh sets a posture; the operator chooses that, not the installer")
