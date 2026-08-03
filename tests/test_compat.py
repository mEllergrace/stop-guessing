"""M0 gate: the vendored tree is intact and the corpus behaves as recorded.

The full replay takes ~90s, so it is marked `slow` and excluded from the default run. Everything
that can be checked without spawning 219 subprocesses is checked here and runs in milliseconds.
"""

from __future__ import annotations

import json

import pytest

from stop_guessing.compat import manifest
from stop_guessing.compat.corpus import CORPUS
from stop_guessing.compat.replay import HOOK_ORDER, normalise, run_case
from stop_guessing.version import repo_root

GOLDEN = repo_root() / "fixtures" / "compat-golden.json"


def _golden() -> dict:
    return json.loads(GOLDEN.read_text(encoding="utf-8"))


# ── the vendored tree ────────────────────────────────────────────────────────


def test_vendored_tree_is_intact():
    result = manifest.verify()
    assert result["intact"], (
        f"vendored no-noodles drifted: changed={result['changed']} "
        f"missing={result['missing']} untracked={result['untracked']}"
    )


def test_vendored_check_before_build_is_the_hardened_version():
    """moonsoup/no-noodles#1 — the repo copy is 62 lines, the hardened one is 125.

    Vendoring the repo copy would silently drop marker validation, the workflows/ guard and the
    candidate search. This asserts we carry the good one.
    """
    src = manifest.vendored_dir() / "check_before_build.sh"
    text = src.read_text(encoding="utf-8")
    assert len(text.splitlines()) > 100, "vendored the stale 62-line check_before_build.sh"
    assert "build-ok" in text
    assert "workflows" in text, "missing the workflows/ guard from the hardened version"


def test_manifest_covers_every_vendored_file():
    tracked = set(manifest.load())
    on_disk = {
        p.name
        for p in manifest.vendored_dir().iterdir()
        if p.is_file() and p.name != manifest.MANIFEST_NAME
    }
    assert tracked == on_disk


# ── the corpus ───────────────────────────────────────────────────────────────


def test_corpus_meets_the_m0_size_bar():
    assert len(CORPUS) >= 60, f"M0 requires >=60 payloads, corpus has {len(CORPUS)}"


def test_corpus_ids_are_unique():
    ids = [c.id for c in CORPUS]
    assert len(ids) == len(set(ids))


def test_corpus_exercises_frequency_semantics():
    """no_noodle.sh blocks the *second* occurrence, so a corpus of single shots proves nothing."""
    assert any(c.repeat > 1 for c in CORPUS)


def test_corpus_covers_both_projects():
    assert len({c.cwd for c in CORPUS}) >= 2


def test_corpus_covers_every_guarded_shape():
    commands = " ".join(c.tool_input.get("command", "") for c in CORPUS)
    assert "| python3" in commands
    assert "| jq" in commands
    assert "base64 -d" in commands
    assert "wget" in commands
    assert "# noodle-ok" in commands
    assert "# risk-ok" in commands


# ── the golden ───────────────────────────────────────────────────────────────


def test_golden_exists_and_is_shaped():
    g = _golden()
    assert g["_cases"] == len(CORPUS)
    assert g["_invocations"] == len(CORPUS) * len(HOOK_ORDER_PRESENT())
    assert g["outcomes"]


def HOOK_ORDER_PRESENT() -> list[str]:
    """Hooks actually present in the vendored tree, in dispatcher order."""
    present = {p.name for p in manifest.vendored_dir().iterdir()}
    return [h for h in HOOK_ORDER if h in present]


def test_golden_records_blocks_and_passes():
    outcomes = _golden()["outcomes"]
    exits = {v["exit_code"] for v in outcomes.values()}
    assert exits <= {0, 2}, f"unexpected exit codes in golden: {exits - {0, 2}}"
    assert any(v["exit_code"] == 2 for v in outcomes.values()), "golden records no blocks at all"
    assert any(v["exit_code"] == 0 for v in outcomes.values())


def test_golden_has_no_absolute_temp_paths():
    """Temp paths differ per run; leaving them in would make the golden non-deterministic."""
    blob = json.dumps(_golden()["outcomes"])
    assert "sg-replay-" not in blob


@pytest.mark.parametrize(
    ("case_id", "hook"),
    [
        ("r1-fetch-pipe-python-2nd", "no_noodle.sh"),
        ("r1-b64-decode-2nd", "no_noodle.sh"),
        ("r4-scripts-py-nomarker", "check_before_build.sh"),
        ("r4-short-marker", "check_before_build.sh"),
        ("r4-workflow-json", "check_before_build.sh"),
    ],
)
def test_golden_blocks_what_must_block(case_id, hook):
    assert _golden()["outcomes"][f"{case_id}::{hook}"]["exit_code"] == 2


@pytest.mark.parametrize(
    ("case_id", "hook"),
    [
        ("r1-fetch-pipe-python-1st", "no_noodle.sh"),
        ("r1-escape-noodle-ok", "no_noodle.sh"),
        ("r1-escape-noodle-ok-b64", "no_noodle.sh"),
        ("r1-project-b-1st", "no_noodle.sh"),
        ("r1-pipe-to-sh-not-guarded", "no_noodle.sh"),
        ("r4-test-exempt-prefix", "check_before_build.sh"),
        ("r4-valid-marker", "check_before_build.sh"),
        ("r4-outside-scripts", "check_before_build.sh"),
        ("risk-rm-rf-root", "risk_gate.sh"),
        ("pass-read", "no_noodle.sh"),
    ],
)
def test_golden_allows_what_must_pass(case_id, hook):
    assert _golden()["outcomes"][f"{case_id}::{hook}"]["exit_code"] == 0


def test_risk_gate_is_off_by_default_across_the_whole_corpus():
    """Every risk_gate invocation should pass: the gate ships off, as it did in no-noodles."""
    outcomes = _golden()["outcomes"]
    blocked = [k for k, v in outcomes.items() if k.endswith("::risk_gate.sh") and v["exit_code"] != 0]
    assert not blocked, f"risk_gate blocked with default config: {blocked}"


# ── live replay (slow) ───────────────────────────────────────────────────────


@pytest.mark.slow
@pytest.mark.parametrize("case_id", ["r1-fetch-pipe-python-2nd", "r4-valid-marker", "pass-read"])
def test_live_replay_matches_golden(case_id):
    case = next(c for c in CORPUS if c.id == case_id)
    observed = normalise(run_case(case))
    expected = {k: v for k, v in _golden()["outcomes"].items() if k.startswith(f"{case_id}::")}
    assert observed == expected
