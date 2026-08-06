"""VERSION is the single source of truth, and digests behave under adversarial input."""

from __future__ import annotations

import hashlib
import tomllib

import pytest

from stop_guessing.artifacts.digest import (
    bytes_digest,
    file_digest,
    snapshot_files,
    verify_manifest,
)
from stop_guessing.version import SEMVER, __version__, read_version, repo_root

# ── version ──────────────────────────────────────────────────────────────────


def test_version_is_semver():
    assert SEMVER.match(__version__)


def test_pyproject_version_comes_from_the_version_file():
    """rich-text drifted (plugin.json 0.2.14 vs manifest.yaml 0.3.0) because both were hand-kept.

    Here pyproject reads VERSION dynamically, so this asserts the wiring rather than a literal.
    """
    data = tomllib.loads((repo_root() / "pyproject.toml").read_text(encoding="utf-8"))
    assert "version" in data["project"]["dynamic"]
    assert data["tool"]["setuptools"]["dynamic"]["version"]["file"] == "VERSION"


def test_readme_states_the_same_version():
    readme = (repo_root() / "README.md").read_text(encoding="utf-8")
    assert f"Version {__version__}" in readme


def test_changelog_has_an_entry_for_this_version():
    changelog = (repo_root() / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"[{__version__}]" in changelog


def test_claims_meta_version_agrees():
    yaml = pytest.importorskip("yaml")
    claims = yaml.safe_load((repo_root() / "docs" / "claims.yaml").read_text(encoding="utf-8"))
    assert claims["meta"]["version"] == __version__


def test_read_version_refuses_garbage(tmp_path, monkeypatch):
    """An unreadable or malformed version is a fault, not a thing to guess around."""
    import stop_guessing.version as v

    monkeypatch.setattr(v, "repo_root", lambda: tmp_path)
    (tmp_path / "VERSION").write_text("not-a-version\n")
    with pytest.raises(ValueError, match="not a bare semver"):
        read_version()


def test_read_version_falls_back_to_the_packaged_copy(tmp_path, monkeypatch):
    """#68: a wheel has no checkout above it, and this used to raise at import time.

    `repo_root()` falls back to the package parent — `site-packages` under a wheel — so resolving
    VERSION through it alone made `import stop_guessing` fail outright for every non-editable
    install. The packaged copy is the second candidate.
    """
    import stop_guessing.version as v

    monkeypatch.setattr(v, "repo_root", lambda: tmp_path)   # an empty "root"
    assert SEMVER.match(read_version()), "must resolve from stop_guessing/data/VERSION"


def test_read_version_refuses_when_no_candidate_resolves(tmp_path, monkeypatch):
    """Still a hard failure when the version genuinely cannot be found — never invented."""
    import stop_guessing.version as v

    monkeypatch.setattr(v, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(v, "__file__", str(tmp_path / "pkg" / "version.py"))
    with pytest.raises(ValueError, match="cannot read VERSION"):
        read_version()


# ── digests ──────────────────────────────────────────────────────────────────


def test_file_digest_matches_hashlib(tmp_path):
    p = tmp_path / "a.bin"
    payload = b"chain of custody" * 1000
    p.write_bytes(payload)
    assert file_digest(p) == hashlib.sha256(payload).hexdigest()


def test_file_digest_is_full_length_not_a_prefix(tmp_path):
    """in-toto matches subjects purely by digest; a truncated digest is not a subject."""
    p = tmp_path / "a.bin"
    p.write_bytes(b"x")
    assert len(file_digest(p)) == 64


def test_file_digest_streams_large_files(tmp_path):
    p = tmp_path / "big.bin"
    payload = b"\x00" * (3 * (1 << 20) + 17)  # crosses the 1 MiB chunk boundary
    p.write_bytes(payload)
    assert file_digest(p) == hashlib.sha256(payload).hexdigest()


def test_file_digest_returns_none_for_missing(tmp_path):
    assert file_digest(tmp_path / "nope") is None


def test_file_digest_returns_none_for_directory(tmp_path):
    assert file_digest(tmp_path) is None


def test_bytes_digest_matches(tmp_path):
    assert bytes_digest(b"abc") == hashlib.sha256(b"abc").hexdigest()


def test_snapshot_distinguishes_absent_from_present(tmp_path):
    (tmp_path / "there.txt").write_text("hello")
    snap = snapshot_files(tmp_path, ["there.txt", "gone.txt"])
    assert snap["there.txt"]["present"] is True
    assert snap["there.txt"]["size"] == 5
    assert snap["gone.txt"]["present"] is False
    assert snap["gone.txt"]["digest"] is None


def test_verify_manifest_separates_changed_from_missing(tmp_path):
    (tmp_path / "kept.txt").write_text("a")
    (tmp_path / "edited.txt").write_text("b")
    m = {
        "kept.txt": file_digest(tmp_path / "kept.txt"),
        "edited.txt": hashlib.sha256(b"original").hexdigest(),
        "vanished.txt": hashlib.sha256(b"whatever").hexdigest(),
    }
    result = verify_manifest(tmp_path, m)
    assert result["ok"] == ["kept.txt"]
    assert result["changed"] == ["edited.txt"]
    assert result["missing"] == ["vanished.txt"]


# ── the workflow guard: never prove against an unstamped tree ────────────────


def test_prove_refuses_when_the_tree_is_not_stamped(tmp_path, monkeypatch):
    """Twice during 0.5.x the version was stamped AFTER proving.

    Every proof record pins the version, so all twenty-one died at once and the gate reported a
    wall of `version changed since this proof` findings that looked like a regression and meant
    only "you stamped last". Two full prove runs discarded. A doc note was not enough; this makes
    it mechanical.
    """
    import subprocess
    import sys

    from stop_guessing.version import repo_root

    repo = repo_root()
    version_file = repo / "VERSION"
    original = version_file.read_text(encoding="utf-8")
    try:
        version_file.write_text("9.9.9\n", encoding="utf-8")
        res = subprocess.run(  # noqa: S603
            [sys.executable, "-m", "stop_guessing.cli.main", "prove", "--claim", "CLAIM-01"],
            capture_output=True, text=True, cwd=str(repo), timeout=600,
            stdin=subprocess.DEVNULL)
        assert res.returncode == 2, f"prove ran against an unstamped tree: {res.stdout[-400:]}"
        assert "REFUSED" in res.stdout
        assert "stamp_version.py" in res.stdout, "the refusal does not say how to fix it"
    finally:
        version_file.write_text(original, encoding="utf-8")


def test_the_drift_guard_is_quiet_on_a_stamped_tree():
    """The control. A guard that always refuses would make `prove` unusable."""
    from stop_guessing.cli.cmd_prove import _version_drift

    assert _version_drift() == [], (
        "the tree is stamped, yet the guard reports drift; it would refuse every prove run")


def test_the_drift_guard_has_a_documented_override():
    """Never close an option: someone may have a reason, and it must be reachable."""
    import subprocess
    import sys

    from stop_guessing.version import repo_root

    res = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "stop_guessing.cli.main", "prove", "--help"],
        capture_output=True, text=True, cwd=str(repo_root()), timeout=300,
        stdin=subprocess.DEVNULL)
    assert "--allow-version-drift" in res.stdout
