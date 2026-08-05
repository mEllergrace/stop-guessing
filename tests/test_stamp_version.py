"""Version drift is what happens when stamping is manual.

rich-text already drifted this way — `plugin.json` 0.2.14 against `manifest.yaml` 0.3.0 — and the
plan named it as the thing not to repeat. It got repeated anyway: bumping VERSION to 0.4.0 by hand
left three manifests declaring 0.3.0, because a human (and a model) stamps the files they remember.

So these tests are about the ones nobody remembers.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from stamp_version import declared_versions, stamp  # noqa: E402


def _repo(tmp_path: Path, version: str = "1.2.3") -> Path:
    (tmp_path / "VERSION").write_text(f"{version}\n", encoding="utf-8")
    (tmp_path / ".claude-plugin").mkdir()
    (tmp_path / ".claude-plugin" / "marketplace.json").write_text(
        json.dumps({"name": "sg", "version": "0.0.1"}), encoding="utf-8")
    deep = tmp_path / ".agents" / "plugins" / "sg" / ".codex-plugin"
    deep.mkdir(parents=True)
    (deep / "plugin.json").write_text(
        json.dumps({"name": "sg", "version": "0.0.1"}), encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "sg"\nversion = "0.0.1"\n', encoding="utf-8")
    return tmp_path


def test_finds_every_declared_version_including_nested_manifests(tmp_path):
    repo = _repo(tmp_path)
    found = declared_versions(repo)
    rels = {p for p in found}
    assert any("marketplace.json" in r for r in rels)
    assert any(".codex-plugin/plugin.json" in r.replace("\\", "/") for r in rels), rels
    assert any("pyproject.toml" in r for r in rels)


def test_stamping_updates_all_of_them(tmp_path):
    repo = _repo(tmp_path)
    changed = stamp(repo, "1.2.3")
    assert len(changed) >= 3
    assert json.loads((repo / ".claude-plugin" / "marketplace.json").read_text())["version"] == "1.2.3"
    deep = repo / ".agents" / "plugins" / "sg" / ".codex-plugin" / "plugin.json"
    assert json.loads(deep.read_text())["version"] == "1.2.3"
    assert 'version = "1.2.3"' in (repo / "pyproject.toml").read_text()


def test_stamping_is_idempotent(tmp_path):
    repo = _repo(tmp_path)
    stamp(repo, "1.2.3")
    assert stamp(repo, "1.2.3") == [], "a second stamp must change nothing"


def test_check_mode_reports_drift_without_writing(tmp_path):
    repo = _repo(tmp_path)
    before = (repo / ".claude-plugin" / "marketplace.json").read_text()
    drifted = stamp(repo, "1.2.3", check_only=True)
    assert drifted, "drift must be reported"
    assert (repo / ".claude-plugin" / "marketplace.json").read_text() == before, \
        "check mode must not write"


def test_json_stays_valid_and_keeps_its_other_keys(tmp_path):
    repo = _repo(tmp_path)
    p = repo / ".claude-plugin" / "marketplace.json"
    p.write_text(json.dumps({"name": "sg", "version": "0.0.1",
                             "plugins": [{"name": "a"}], "description": "keep me"}),
                 encoding="utf-8")
    stamp(repo, "1.2.3")
    doc = json.loads(p.read_text())
    assert doc["version"] == "1.2.3"
    assert doc["description"] == "keep me"
    assert doc["plugins"] == [{"name": "a"}]


def test_a_marketplace_that_versions_only_its_plugins_entries_is_stamped(tmp_path):
    """The exact miss: no top-level "version", so the file reported as agreeing while it drifted."""
    repo = _repo(tmp_path)
    p = repo / ".claude-plugin" / "marketplace.json"
    p.write_text(json.dumps({"name": "sg", "owner": "x",
                             "plugins": [{"name": "sg", "version": "0.0.1"}]}), encoding="utf-8")
    changed = stamp(repo, "1.2.3")
    assert json.loads(p.read_text())["plugins"][0]["version"] == "1.2.3"
    assert any("marketplace.json" in c for c in changed)


def test_claims_meta_version_is_stamped(tmp_path):
    repo = _repo(tmp_path)
    (repo / "docs").mkdir()
    (repo / "docs" / "claims.yaml").write_text(
        "meta:\n  version: 0.0.1\n  aicm_version: 1.1.0\nclaims: []\n", encoding="utf-8")
    stamp(repo, "1.2.3")
    body = (repo / "docs" / "claims.yaml").read_text()
    assert "version: 1.2.3" in body
    assert "aicm_version: 1.1.0" in body, "only the package version moves, not the spec versions"


def test_a_file_with_no_version_key_is_left_alone(tmp_path):
    repo = _repo(tmp_path)
    other = repo / ".claude-plugin" / "hooks.json"
    other.write_text(json.dumps({"hooks": {}}), encoding="utf-8")
    stamp(repo, "1.2.3")
    assert json.loads(other.read_text()) == {"hooks": {}}
