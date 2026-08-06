"""The installer must survive `set -u`, and must not claim a tier it did not deliver.

R2-007 was the sharpest finding of round two: the `--isolated` branch expanded `$CLAUDE_DIR`, a
variable the script never assigns, under `set -euo pipefail`. The installer aborted on the first
expansion. Nothing caught it because nothing ever executed that branch — the tier-2 path had no
test at all, and its audit predicate was satisfied by finding the string `/Library/LaunchDaemons`
in the file.

These tests execute the shell, with `launchctl`/`dscl`/`pip` stubbed, so a variable that is not
set fails here rather than on a user's machine.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
INSTALL = REPO / "install.sh"


def test_the_installer_parses_under_strict_mode():
    res = subprocess.run(["bash", "-n", str(INSTALL)], capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, res.stderr


def test_no_expansion_of_an_unassigned_uppercase_config_variable():
    """The exact R2-007 shape: a variable used but never assigned, fatal under `set -u`."""
    import re

    body = INSTALL.read_text(encoding="utf-8")
    code = re.sub(r"(?m)^\s*#.*$", "", body)          # comments may discuss it; code may not use it
    assert not re.search(r"\$\{?CLAUDE_DIR\b", code), \
        "install.sh expands $CLAUDE_DIR, which it never assigns; under set -u this aborts"


@pytest.fixture
def stub_bin(tmp_path):
    """Stubs for the system commands the isolated branch would otherwise invoke."""
    d = tmp_path / "bin"
    d.mkdir()
    for name in ("launchctl", "dscl", "dseditgroup", "chown", "install"):
        f = d / name
        f.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        f.chmod(0o755)
    # `id` must report that the service account exists, so the tier-2 branch is entered at all.
    idf = d / "id"
    idf.write_text(
        "#!/usr/bin/env bash\n"
        'if [ "$1" = "-u" ] && [ -n "${2:-}" ]; then echo 499; exit 0; fi\n'
        'if [ "$1" = "-u" ]; then echo 501; exit 0; fi\n'
        'if [ "$1" = "-un" ]; then echo tester; exit 0; fi\n'
        'if [ -n "${1:-}" ]; then exit 0; fi\n'
        "exit 0\n", encoding="utf-8")
    idf.chmod(0o755)
    return d


def test_the_isolated_branch_runs_without_an_unset_variable(tmp_path, stub_bin):
    """Execute the branch that R2-007 said aborts. A `set -u` failure surfaces as exit 1 here."""
    profile = tmp_path / "claude"
    (profile / "hooks").mkdir(parents=True)
    (profile / "settings.json").write_text("{}", encoding="utf-8")

    env = dict(os.environ)
    env["PATH"] = f"{stub_bin}:{env['PATH']}"
    env["CLAUDE_CONFIG_DIR"] = str(profile)

    res = subprocess.run(
        ["bash", str(INSTALL), "--profile", str(profile), "--isolated"],
        capture_output=True, text=True, timeout=1800, env=env, cwd=str(REPO),
    )
    combined = res.stdout + res.stderr
    assert "unbound variable" not in combined, f"set -u failure in the isolated branch:\n{combined}"
    assert res.returncode == 0, f"installer exited {res.returncode}:\n{combined[-1500:]}"


def test_the_isolated_branch_does_not_claim_tier_two(tmp_path, stub_bin):
    """It stages the plist and says what is missing. Claiming an undeliverable tier writes a false
    isolation_tier into every record, which is worse than not offering the tier."""
    profile = tmp_path / "claude"
    (profile / "hooks").mkdir(parents=True)
    (profile / "settings.json").write_text("{}", encoding="utf-8")

    env = dict(os.environ)
    env["PATH"] = f"{stub_bin}:{env['PATH']}"
    res = subprocess.run(
        ["bash", str(INSTALL), "--profile", str(profile), "--isolated"],
        capture_output=True, text=True, timeout=1800, env=env, cwd=str(REPO),
    )
    out = res.stdout + res.stderr
    assert "TIER 2 IS NOT INSTALLED" in out, "the installer must say plainly what it did not do"
    assert "Installing TIER 1" in out
    assert "installed TIER 2" not in out, "tier 2 was claimed without being delivered"


def test_the_staged_plist_is_well_formed_and_carries_a_key(tmp_path, stub_bin):
    """R2-008/R2-009: an interpreter that exists, and --keyfile without which the daemon exits 2."""
    profile = tmp_path / "claude"
    (profile / "hooks").mkdir(parents=True)
    (profile / "settings.json").write_text("{}", encoding="utf-8")

    env = dict(os.environ)
    env["PATH"] = f"{stub_bin}:{env['PATH']}"
    subprocess.run(["bash", str(INSTALL), "--profile", str(profile), "--isolated"],
                   capture_output=True, text=True, timeout=1800, env=env, cwd=str(REPO))

    staged = profile / "stop-guessing" / "com.mellergrace.stop-guessing.cocd.plist"
    assert staged.is_file(), "the tier-2 plist was not staged"
    body = staged.read_text(encoding="utf-8")

    assert "--keyfile" in body, "the daemon would exit 2 with no key"
    assert "runtime/bin/python" not in body, \
        "pip --target creates a package directory, not an interpreter"
    assert "UserName" in body, "without UserName the daemon runs as the invoking user"

    import plistlib

    parsed = plistlib.loads(staged.read_bytes())        # must be valid plist, not just text
    interp = parsed["ProgramArguments"][0]
    assert Path(interp).exists(), f"the plist names an interpreter that does not exist: {interp}"
    assert shutil.which("python3"), "sanity: python3 should be resolvable in this environment"


def test_the_installer_registers_every_event_the_plugin_does(tmp_path, stub_bin):
    """R2-026: two supported install paths with different evidence is two different products."""
    import json

    profile = tmp_path / "claude"
    (profile / "hooks").mkdir(parents=True)
    (profile / "settings.json").write_text("{}", encoding="utf-8")

    env = dict(os.environ)
    env["PATH"] = f"{stub_bin}:{env['PATH']}"
    res = subprocess.run(["bash", str(INSTALL), "--profile", str(profile)],
                         capture_output=True, text=True, timeout=1800, env=env, cwd=str(REPO))
    assert res.returncode == 0, (res.stdout + res.stderr)[-1200:]

    installed = set(json.loads((profile / "settings.json").read_text(encoding="utf-8"))["hooks"])
    plugin = set(json.loads(
        (REPO / ".claude-plugin/plugins/stop-guessing/hooks/hooks.json").read_text(
            encoding="utf-8"))["hooks"])
    missing = plugin - installed
    assert not missing, f"install.sh omits events the plugin registers: {sorted(missing)}"


def test_each_generated_hook_script_names_its_event(tmp_path, stub_bin):
    profile = tmp_path / "claude"
    (profile / "hooks").mkdir(parents=True)
    (profile / "settings.json").write_text("{}", encoding="utf-8")
    env = dict(os.environ)
    env["PATH"] = f"{stub_bin}:{env['PATH']}"
    subprocess.run(["bash", str(INSTALL), "--profile", str(profile)],
                   capture_output=True, text=True, timeout=1800, env=env, cwd=str(REPO))

    stop_hook = profile / "hooks" / "coc_stop.sh"
    assert stop_hook.is_file(), "the Stop hook script was not written"
    body = stop_hook.read_text(encoding="utf-8")
    assert "hook_lifecycle Stop" in body, f"the Stop hook does not dispatch its event:\n{body}"


def test_both_install_paths_deliver_every_declared_slash_command(tmp_path, stub_bin):
    """CLAIM-17 declares /no-noodle and /noodle-options; §10.1 says they survive supersession.

    Neither path shipped them. A user who superseded no-noodles and then removed it lost two slash
    commands the claim said would keep working — the claim asserted a surface the product did not
    deliver. Withdrawing the declaration would have cleared the finding by shrinking the claim,
    which is what `prove/scope.py` now catches, so the docs are vendored and installed instead.
    """
    profile = tmp_path / "claude"
    (profile / "hooks").mkdir(parents=True)
    (profile / "settings.json").write_text("{}", encoding="utf-8")
    env = dict(os.environ)
    env["PATH"] = f"{stub_bin}:{env['PATH']}"
    res = subprocess.run(["bash", str(INSTALL), "--profile", str(profile)],
                         capture_output=True, text=True, timeout=1800, env=env, cwd=str(REPO))
    assert res.returncode == 0, (res.stdout + res.stderr)[-1200:]

    expected = {"custody", "custody-options", "no-noodle", "noodle-options"}
    for doc in sorted(expected):
        # commands/ is what registers the slash command; skills/ is what makes it loadable
        # (the 2026-07-29 finding: a flat .md under skills/ alone is never loaded).
        assert (profile / "commands" / f"{doc}.md").is_file(), \
            f"install.sh did not install /{doc} into commands/"
        assert (profile / "skills" / f"{doc}.md").is_file(), \
            f"install.sh did not install {doc}.md into skills/"

    plugin_cmds = {p.stem for p in
                   (REPO / ".claude-plugin/plugins/stop-guessing/commands").glob("*.md")}
    missing = expected - plugin_cmds
    assert not missing, f"the plugin ships fewer slash commands than install.sh: {sorted(missing)}"


def test_the_vendored_noodle_docs_are_byte_identical_to_upstream():
    """Vendored means copied. A rewritten doc is a fork wearing upstream's name."""
    import hashlib

    vendored = REPO / "stop_guessing/compat/nonoodles"
    manifest = {}
    for line in (vendored / "MANIFEST.sha256").read_text(encoding="utf-8").splitlines():
        if line.strip():
            parts = line.split()
            manifest[parts[-1]] = parts[0]

    for doc in ("no-noodle.md", "noodle-options.md"):
        assert doc in manifest, f"{doc} is vendored but not in MANIFEST.sha256"
        got = hashlib.sha256((vendored / doc).read_bytes()).hexdigest()
        assert got == manifest[doc], f"{doc} does not match its manifest digest"


def test_the_wheel_would_ship_the_vendored_tree():
    """A wheel that omits compat/ makes the supersession promise undeliverable from a wheel.

    It passed from a checkout, which is exactly how packaging gaps hide.
    """
    import tomllib

    pyproject = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    globs = pyproject["tool"]["setuptools"]["package-data"]["stop_guessing"]
    for need in ("compat/nonoodles/*.sh", "compat/nonoodles/*.md", "compat/nonoodles/*.json"):
        assert need in globs, f"package-data does not ship {need}"
