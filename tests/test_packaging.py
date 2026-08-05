"""The wheel must work outside a checkout — SG-HARD-035 (#68).

This was worse than the audit reported. `read_version()` resolved VERSION through `repo_root()`,
whose fallback is the *package parent* — `site-packages` under a wheel, where no VERSION exists —
and `__version__` is evaluated at import. So `import stop_guessing` raised outright: the wheel was
not merely missing data, it was unimportable.

Nothing caught it because every developer machine installs editable from the checkout, and
`install.sh` copied the extras by hand, which hid the broken distribution path rather than fixing
it. Inspecting the wheel's CONTENTS did not catch it either — the files were present and the code
still could not find them. Only installing into a clean interpreter and running it did.

Hence this file: the fast tests assert the declaration, and the slow one actually builds, installs
and runs.
"""

from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
REQUIRED_DATA = (
    "data/VERSION",
    "data/rules/classify.yaml",
    "data/policy/coc.policy.d/10-base.yaml",
)


# ── fast: the declaration ────────────────────────────────────────────────────


def test_package_data_is_declared():
    body = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    assert "[tool.setuptools.package-data]" in body
    assert "data/policy/coc.policy.d/*.yaml" in body
    assert "data/rules/*.yaml" in body


def test_sdist_manifest_exists():
    assert (REPO / "MANIFEST.in").is_file(), "an sdist needs the data too, not just the wheel"


def test_the_runtime_data_lives_inside_the_package():
    for rel in REQUIRED_DATA:
        assert (REPO / "stop_guessing" / rel).is_file(), f"missing packaged data: {rel}"


def test_resolvers_do_not_reach_for_the_repository_root():
    """`repo_root()` answers 'where is the checkout', which a wheel cannot answer."""
    import re

    for mod in ("artifacts/classify.py", "cli/gate.py", "cli/cmd_ops.py", "prove/procedures.py"):
        src = (REPO / "stop_guessing" / mod).read_text(encoding="utf-8")
        src = re.sub(r'"""(?:.|\n)*?"""', "", src)
        src = re.sub(r"(?m)#.*$", "", src)
        assert 'repo_root() / "policy"' not in src, f"{mod} still builds a policy path from the checkout"
        assert 'repo_root() / "rules"' not in src, f"{mod} still builds a rules path from the checkout"


def test_data_dir_falls_back_to_the_packaged_copy(monkeypatch, tmp_path):
    """With no checkout above it, resolution must land inside the package."""
    from stop_guessing import version as v

    monkeypatch.setattr(v, "repo_root", lambda: tmp_path)  # an empty "root"
    resolved = v.data_dir()
    assert resolved == Path(v.__file__).resolve().parent / "data"
    assert (resolved / "policy" / "coc.policy.d").is_dir()


# ── slow: build it, install it, run it ───────────────────────────────────────


@pytest.mark.slow
def test_a_built_wheel_installs_and_runs_outside_the_repository(tmp_path):
    wheels = tmp_path / "wheels"
    subprocess.run([sys.executable, "-m", "pip", "wheel", "--no-deps", "-w", str(wheels),
                    str(REPO)], check=True, capture_output=True, timeout=900)
    built = sorted(wheels.glob("stop_guessing-*.whl"))
    assert built, "no wheel was produced"

    names = zipfile.ZipFile(built[-1]).namelist()
    for rel in REQUIRED_DATA:
        assert any(n.endswith(rel) for n in names), f"{rel} is not in the wheel"

    venv = tmp_path / "venv"
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True, timeout=900)
    py = venv / "bin" / "python"
    subprocess.run([str(py), "-m", "pip", "install", "-q", str(built[-1]), "pyyaml", "openpyxl"],
                   check=True, capture_output=True, timeout=1800)

    # cwd is deliberately NOT the repository: that is the condition that was broken.
    probe = (
        "from stop_guessing.version import __version__, policy_dir;"
        "from stop_guessing.policy.engine import load;"
        "from stop_guessing.artifacts.classify import DEFAULT_RULES;"
        "ps = load(policy_dir());"
        "print(__version__, len(ps.policies), DEFAULT_RULES.is_file())"
    )
    res = subprocess.run([str(py), "-c", probe], capture_output=True, text=True,
                         cwd=str(tmp_path), timeout=900)
    assert res.returncode == 0, f"the installed package could not run: {res.stderr[-600:]}"
    version, n_policies, rules_present = res.stdout.split()
    assert version == (REPO / "VERSION").read_text(encoding="utf-8").strip()
    assert int(n_policies) > 0, "no policies loaded from the installed package"
    assert rules_present == "True"
