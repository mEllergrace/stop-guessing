#!/usr/bin/env python3
"""Tests for `set_posture.py` — written before it ran against a live profile.

Every case here uses a tmp_path profile. The one thing this script does that cannot be undone is
write to a real `~/.claude*`, so the write path, the read-modify-write preservation, the managed
floor and the legacy file are all exercised on fixtures first.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import set_posture as sp  # noqa: E402


def _write(profile: Path, name: str, payload) -> None:
    profile.mkdir(parents=True, exist_ok=True)
    (profile / name).write_text(
        payload if isinstance(payload, str) else json.dumps(payload), encoding="utf-8")


def test_it_writes_the_posture_into_an_absent_config(tmp_path):
    res = sp.set_posture(tmp_path, "observe")
    assert res["wrote"] and res["changed"]
    assert json.loads((tmp_path / sp.CONFIG).read_text())["posture"] == "observe"


def test_it_preserves_every_other_key(tmp_path):
    """The rule from custody-options.md: other keys belong to someone else.

    no-noodles owns `no_ad_hoc_probes`, `check_before_build` and `risk_scoring` in this same file.
    Clobbering them while turning a posture down would silently disable the operator's other
    controls — a worse version of the bug being fixed.
    """
    _write(tmp_path, sp.CONFIG, {"posture": "steer", "no_ad_hoc_probes": True,
                                 "check_before_build": False, "risk_scoring": {"threshold": 7}})
    res = sp.set_posture(tmp_path, "observe")
    data = json.loads((tmp_path / sp.CONFIG).read_text())
    assert data == {"posture": "observe", "no_ad_hoc_probes": True,
                    "check_before_build": False, "risk_scoring": {"threshold": 7}}
    assert res["preserved"] == ["check_before_build", "no_ad_hoc_probes", "risk_scoring"]


def test_it_backs_up_before_overwriting(tmp_path):
    _write(tmp_path, sp.CONFIG, {"posture": "steer"})
    sp.set_posture(tmp_path, "observe")
    backups = list(tmp_path.glob("stop-guessing.json.bak-*"))
    assert len(backups) == 1
    assert json.loads(backups[0].read_text())["posture"] == "steer"


def test_dry_run_writes_nothing(tmp_path):
    _write(tmp_path, sp.CONFIG, {"posture": "steer"})
    res = sp.set_posture(tmp_path, "observe", dry_run=True)
    assert res["changed"] and not res["wrote"]
    assert json.loads((tmp_path / sp.CONFIG).read_text())["posture"] == "steer"


def test_setting_the_same_posture_is_a_no_op_and_leaves_no_backup(tmp_path):
    _write(tmp_path, sp.CONFIG, {"posture": "observe"})
    res = sp.set_posture(tmp_path, "observe")
    assert not res["changed"] and not res["wrote"]
    assert not list(tmp_path.glob("stop-guessing.json.bak-*"))


def test_an_unparseable_config_is_not_silently_discarded_into_a_new_one(tmp_path):
    """Garbage in the file means the resolver ignores that layer, so the write must still land —
    but a backup must exist, because the bytes it replaced were not recoverable otherwise."""
    _write(tmp_path, sp.CONFIG, "{not json")
    sp.set_posture(tmp_path, "observe")
    assert json.loads((tmp_path / sp.CONFIG).read_text()) == {"posture": "observe"}
    assert [b.read_text() for b in tmp_path.glob("stop-guessing.json.bak-*")] == ["{not json"]


def test_it_refuses_a_posture_that_is_not_one_of_the_three(tmp_path):
    with pytest.raises(ValueError):
        sp.set_posture(tmp_path, "off")
    assert not (tmp_path / sp.CONFIG).exists()


# --- the resolution chain, as the gate sees it ------------------------------------------------

def test_inspect_reports_the_shipped_default_for_an_empty_profile(tmp_path):
    i = sp.inspect(tmp_path)
    assert i["effective"] == sp.DEFAULT_POSTURE
    assert i["configured"] is None and i["managed"] is None and i["legacy"] is None


def test_inspect_finds_an_explicit_steer_which_is_the_reported_defect(tmp_path):
    """The personal-profile symptom: default is observe, profile resolves to steer anyway."""
    _write(tmp_path, sp.CONFIG, {"posture": "steer"})
    i = sp.inspect(tmp_path)
    assert i["configured"] == "steer"
    assert i["effective"] == "steer" != sp.DEFAULT_POSTURE


def test_inspect_finds_a_legacy_state_file_the_default_change_could_not_reach(tmp_path):
    _write(tmp_path, sp.LEGACY, "steer\n")
    i = sp.inspect(tmp_path)
    assert i["legacy"] == "steer" and i["effective"] == "steer"


def test_the_config_wins_over_the_legacy_file_so_the_legacy_file_need_not_be_deleted(tmp_path):
    _write(tmp_path, sp.LEGACY, "steer\n")
    sp.set_posture(tmp_path, "observe")
    assert sp.inspect(tmp_path)["effective"] == "observe"
    assert (tmp_path / sp.LEGACY).is_file(), "the operator's legacy file was deleted"


def test_a_managed_floor_overrides_the_write_and_this_is_reported_not_hidden(tmp_path):
    """#47: the recorded party must not be able to weaken the policy it is recorded under.

    The script must not claim success here — writing `observe` under a `steer` floor leaves the
    profile still asking, and a tool that printed "set observe" would be lying to the operator.
    """
    _write(tmp_path, sp.MANAGED, {"posture": "steer"})
    res = sp.set_posture(tmp_path, "observe")
    assert res["wrote"] and res["managed"] == "steer"
    assert sp.inspect(tmp_path)["effective"] == "steer"
    assert sp._warn_floor(res) is True


def test_a_managed_floor_at_or_below_the_request_is_not_warned_about(tmp_path):
    _write(tmp_path, sp.MANAGED, {"posture": "observe"})
    res = sp.set_posture(tmp_path, "steer")
    assert sp._warn_floor(res) is False
    assert sp.inspect(tmp_path)["effective"] == "steer"


def test_it_never_writes_managed_json(tmp_path):
    _write(tmp_path, sp.MANAGED, {"posture": "bar"})
    sp.set_posture(tmp_path, "observe")
    assert json.loads((tmp_path / sp.MANAGED).read_text()) == {"posture": "bar"}


def test_inspect_does_not_leak_the_env_var_it_sets(tmp_path):
    """`_effective` mutates CLAUDE_CONFIG_DIR. Leaking it would silently repoint every later call."""
    import os

    before = os.environ.get("CLAUDE_CONFIG_DIR", "<unset>")
    sp.inspect(tmp_path)
    assert os.environ.get("CLAUDE_CONFIG_DIR", "<unset>") == before


# --- the CLI ---------------------------------------------------------------------------------

def test_check_writes_nothing_and_names_the_layer(tmp_path, capsys):
    _write(tmp_path, sp.CONFIG, {"posture": "steer"})
    assert sp.main(["--check", "--profile", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "effective `steer`" in out and "ASKS" in out and sp.CONFIG in out
    assert json.loads((tmp_path / sp.CONFIG).read_text())["posture"] == "steer"


def test_the_cli_exits_nonzero_when_a_floor_blocked_the_change(tmp_path):
    _write(tmp_path, sp.MANAGED, {"posture": "bar"})
    assert sp.main(["observe", "--profile", str(tmp_path)]) == 1


def test_the_cli_requires_a_posture_unless_checking(tmp_path):
    with pytest.raises(SystemExit):
        sp.main(["--profile", str(tmp_path)])


def test_a_bare_invocation_touches_nothing(tmp_path):
    """No --profile, no --all-profiles, no --check must not quietly mean "every profile"."""
    with pytest.raises(SystemExit):
        sp.main(["observe"])
