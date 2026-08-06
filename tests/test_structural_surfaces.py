"""Structural validation of the surfaces a proof run cannot execute — and its controls.

Five declared surfaces (`plugin:`, `skill:`, two `command:`, one more `command:`) need a live agent
session to drive: nothing in a proof run can make Claude Code invoke a slash command. They were
reported as "unvalidated", which conflated two different things — "nobody got round to it" and "not
decidable here" — and only the first is a to-do.

What IS decidable is now decided: the artifact ships, in the right place, with the right shape,
registered where it must be, by BOTH install paths. A structural defect is a blocking finding. What
is not decidable stays not established, and `surface_validated` still means EXECUTION, because
reporting it true on the strength of files being in the right place would be the same overclaim in
a new place.

The load-bearing tests are the negatives. A checker that returns [] whatever you give it would pass
every positive test here and establish nothing.
"""

from __future__ import annotations

import json

import pytest

from stop_guessing.prove.runner import LIVE_SESSION_KINDS, structural_findings
from stop_guessing.version import repo_root

PLUGIN = repo_root() / ".claude-plugin" / "plugins" / "stop-guessing"

DECLARED = ["command:/custody", "command:/no-noodle", "command:/noodle-options",
            "plugin:stop-guessing", "skill:stop-guessing"]


def test_every_declared_live_session_surface_is_structurally_sound():
    for surface in DECLARED:
        assert structural_findings(surface) == [], f"{surface} has a structural defect"


def test_the_claims_still_declare_all_five():
    from stop_guessing.prove import runner

    surfaces = {s for c in runner.load_claims()["claims"] for s in (c.get("surface") or [])}
    for s in DECLARED:
        assert s in surfaces, f"{s} was withdrawn from the claims again"


# ── the controls: each check must be able to fail ────────────────────────────


def test_a_missing_command_file_is_a_finding(monkeypatch, tmp_path):
    """The one that mattered: the plugin shipped no no-noodle.md while CLAIM-17 declared it."""
    monkeypatch.setattr("stop_guessing.prove.runner.repo_root", lambda: tmp_path)
    (tmp_path / ".claude-plugin/plugins/stop-guessing/commands").mkdir(parents=True)
    (tmp_path / "install.sh").write_text("for doc in custody; do :; done\n", encoding="utf-8")
    found = structural_findings("command:/no-noodle")
    assert found, "a slash command the plugin does not ship was reported sound"
    assert "commands/no-noodle.md" in " ".join(found)


def test_a_command_the_installer_skips_is_a_finding(monkeypatch, tmp_path):
    """Two install paths delivering different products is two different products."""
    monkeypatch.setattr("stop_guessing.prove.runner.repo_root", lambda: tmp_path)
    cmds = tmp_path / ".claude-plugin/plugins/stop-guessing/commands"
    cmds.mkdir(parents=True)
    (cmds / "no-noodle.md").write_text("# doc\n", encoding="utf-8")
    (tmp_path / "install.sh").write_text("for doc in custody; do :; done\n", encoding="utf-8")
    found = structural_findings("command:/no-noodle")
    assert any("install.sh" in f for f in found), found


def test_a_skill_without_frontmatter_is_a_finding(monkeypatch, tmp_path):
    monkeypatch.setattr("stop_guessing.prove.runner.repo_root", lambda: tmp_path)
    d = tmp_path / ".claude-plugin/plugins/stop-guessing/skills/stop-guessing"
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text("no frontmatter here\n", encoding="utf-8")
    found = structural_findings("skill:stop-guessing")
    assert any("frontmatter" in f for f in found), found


def test_a_flat_skill_md_is_a_finding(monkeypatch, tmp_path):
    """The 2026-07-29 finding: a flat .md under skills/ is written to disk and never loaded."""
    monkeypatch.setattr("stop_guessing.prove.runner.repo_root", lambda: tmp_path)
    d = tmp_path / ".claude-plugin/plugins/stop-guessing/skills"
    d.mkdir(parents=True)
    (d / "stop-guessing.md").write_text("---\nname: x\n---\n", encoding="utf-8")
    assert structural_findings("skill:stop-guessing"), "a flat skill .md was accepted"


def test_a_plugin_version_mismatch_is_a_finding(monkeypatch, tmp_path):
    monkeypatch.setattr("stop_guessing.prove.runner.repo_root", lambda: tmp_path)
    d = tmp_path / ".claude-plugin/plugins/stop-guessing/.claude-plugin"
    d.mkdir(parents=True)
    (d / "plugin.json").write_text(json.dumps({"version": "0.0.1"}), encoding="utf-8")
    (tmp_path / ".claude-plugin/plugins/stop-guessing/hooks").mkdir(parents=True)
    (tmp_path / ".claude-plugin/plugins/stop-guessing/hooks/hooks.json").write_text("{}")
    found = structural_findings("plugin:stop-guessing")
    assert any("0.0.1" in f for f in found), found


def test_a_plugin_registering_no_hooks_is_a_finding(monkeypatch, tmp_path):
    monkeypatch.setattr("stop_guessing.prove.runner.repo_root", lambda: tmp_path)
    d = tmp_path / ".claude-plugin/plugins/stop-guessing/.claude-plugin"
    d.mkdir(parents=True)
    from stop_guessing.version import __version__

    (d / "plugin.json").write_text(json.dumps({"version": __version__}), encoding="utf-8")
    found = structural_findings("plugin:stop-guessing")
    assert any("hooks.json" in f for f in found), found


# ── it must not be mistaken for execution ────────────────────────────────────


def test_structural_soundness_does_not_set_surface_validated():
    """The whole point. Files in the right place is not behaviour through them."""
    from stop_guessing.attest.keys import discover, keyid_of_ledger
    from stop_guessing.prove import runner

    key = discover(None, prefer_keyid=keyid_of_ledger(runner.DEFAULT_LEDGER))
    if not key:
        pytest.skip("no chain key")
    res = runner.attest_self(key[0], runner.DEFAULT_LEDGER)
    a = res["assurance"]
    assert a["surface_validated"] is False, (
        "surface_validated went true while five surfaces cannot be executed here — that is the "
        "overclaim this release exists to prevent")
    assert set(a["surfaces_requiring_live_session"]) == set(DECLARED)


def test_the_verdict_names_the_live_session_surfaces():
    """A verdict that states no reason is what this toolchain exists to stop others shipping."""
    import subprocess
    import sys

    res = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "stop_guessing.cli.main", "attest", "--self"],
        capture_output=True, text=True, cwd=str(repo_root()), timeout=900,
        stdin=subprocess.DEVNULL)
    if "GOAL NOT MET" not in res.stdout:
        pytest.skip("goal met; nothing outstanding to name")
    tail = res.stdout.split("GOAL NOT MET")[1]
    assert tail.strip() != "Outstanding:", "the verdict listed no reason at all"
    for s in DECLARED:
        assert s in tail, f"the verdict does not name {s}"


def test_the_kinds_needing_a_live_session_are_named_explicitly():
    assert set(LIVE_SESSION_KINDS) == {"plugin", "skill", "command"}
