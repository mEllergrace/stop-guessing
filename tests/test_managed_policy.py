"""A floor the recorded party cannot edit — SG-HARD-013/014 (#47, #55).

Project config took precedence with nothing above it, so an agent with ordinary project write
authority could set `posture: observe` to switch off the enforcement it was subject to, and
`protect_ledger: false` to remove the protection on its own evidence — then modify the evidence.
Separately, the policy set was loaded from a writable tree and its digest recorded with nothing to
compare it against, so an edited rule would be faithfully recorded as though it were the authority.

`managed.json` lives in the profile directory, outside project write authority. The rule is
one-directional: a project may TIGHTEN, never loosen.
"""

from __future__ import annotations

import json

import pytest

from stop_guessing.cli.hook_gate import resolve_posture


@pytest.fixture
def profile(tmp_path, monkeypatch):
    cfg = tmp_path / "claude"
    cfg.mkdir()
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(cfg))
    return cfg


def _managed(cfg, **body):
    (cfg / "managed.json").write_text(json.dumps(body), encoding="utf-8")


def _project(tmp_path, **body):
    proj = tmp_path / "proj"
    proj.mkdir(exist_ok=True)
    (proj / ".stop-guessing.json").write_text(json.dumps(body), encoding="utf-8")
    return proj


# ── posture ──────────────────────────────────────────────────────────────────


def test_a_project_cannot_downgrade_below_the_managed_floor(profile, tmp_path):
    _managed(profile, posture="steer")
    proj = _project(tmp_path, posture="observe")
    assert resolve_posture(str(proj)) == "steer", "the project loosened the managed floor"


def test_a_project_may_tighten_above_the_floor(profile, tmp_path):
    """Tightening is legitimate and must keep working — this is a floor, not a lock."""
    _managed(profile, posture="steer")
    proj = _project(tmp_path, posture="bar")
    assert resolve_posture(str(proj)) == "bar"


def test_with_no_managed_file_the_project_still_decides(profile, tmp_path):
    """Absent means no floor: every existing installation behaves exactly as before."""
    proj = _project(tmp_path, posture="observe")
    assert resolve_posture(str(proj)) == "observe"


def test_the_floor_applies_when_no_project_config_exists(profile, tmp_path):
    _managed(profile, posture="bar")
    assert resolve_posture(str(tmp_path / "nowhere")) == "bar"


def test_a_malformed_managed_file_is_ignored_not_fatal(profile, tmp_path):
    (profile / "managed.json").write_text("{ not json", encoding="utf-8")
    proj = _project(tmp_path, posture="observe")
    assert resolve_posture(str(proj)) == "observe"


# ── ledger protection ────────────────────────────────────────────────────────


def test_a_project_cannot_disable_ledger_protection(profile, tmp_path, monkeypatch):
    """The attack in full: switch off the protection on the evidence, then edit the evidence."""
    from stop_guessing.cli.gate import _protect_ledger

    proj = _project(tmp_path, protect_ledger=False)
    monkeypatch.chdir(proj)
    assert _protect_ledger() is True, "project config disabled protection on its own evidence"


def test_an_operator_can_still_disable_it_from_the_managed_file(profile, tmp_path, monkeypatch):
    """The switch stays real — it just has to be set where the recorded party cannot reach."""
    from stop_guessing.cli.gate import _protect_ledger

    _managed(profile, protect_ledger=False)
    monkeypatch.chdir(_project(tmp_path, protect_ledger=True))
    assert _protect_ledger() is False


def test_protection_is_on_by_default(profile, tmp_path, monkeypatch):
    from stop_guessing.cli.gate import _protect_ledger

    monkeypatch.chdir(tmp_path)
    assert _protect_ledger() is True


# ── policy set pinning ───────────────────────────────────────────────────────


def test_a_matching_policy_pin_produces_no_finding(profile, tmp_path):
    from stop_guessing.cli import gate
    from stop_guessing.policy.engine import load
    from stop_guessing.version import policy_dir

    ps = load(policy_dir())
    _managed(profile, expected_policy_digest=ps.digest)
    gate._check_policy_pin(ps)          # must not raise
    led = profile / "stop-guessing" / "ledger" / "custody.jsonl"
    assert not led.exists() or "POLICY SET MISMATCH" not in led.read_text(encoding="utf-8")


def test_a_mismatched_policy_pin_is_recorded_as_critical(profile, tmp_path):
    from stop_guessing.cli import gate
    from stop_guessing.policy.engine import load
    from stop_guessing.version import policy_dir

    (profile / "stop-guessing" / "ledger").mkdir(parents=True)
    _managed(profile, expected_policy_digest="deadbeef" * 8)
    gate._check_policy_pin(load(policy_dir()))
    led = profile / "stop-guessing" / "ledger" / "custody.jsonl"
    assert led.is_file(), "a policy mismatch left no record at all"
    # Parse it rather than substring-matching the serialisation: the ledger writes compact JSON,
    # so '"severity": "critical"' with a space never appears and the assertion would be about
    # formatting rather than about the record.
    rec = json.loads(led.read_text(encoding="utf-8").splitlines()[-1])
    assert "POLICY SET MISMATCH" in rec["detail"]
    assert rec["severity"] == "critical"
    assert rec["known_gaps"], "a policy mismatch must be a stated gap, not only a detail string"


def test_no_pin_means_no_enforcement(profile, tmp_path):
    """Inventing an expectation nobody set would break every existing install."""
    from stop_guessing.cli import gate
    from stop_guessing.policy.engine import load
    from stop_guessing.version import policy_dir

    gate._check_policy_pin(load(policy_dir()))   # no managed.json at all
    led = profile / "stop-guessing" / "ledger" / "custody.jsonl"
    assert not led.exists()
