"""Test isolation for the data location, so a test run cannot write evidence into the repository.

`stop_guessing/paths.py` moved DATA from `$CLAUDE_CONFIG_DIR` to the directory the tool is called
from. That fixed the reported defect — 31 state files pooled in the agent's shared profile — but
moved the pooling rather than ending it: pytest runs with the repository as cwd, so every test that
touched a session wrote `./.stop-guessing/state/<id>.json` into the working tree and *left it
there*.

State is cumulative by design, which is what made this bite. The second run of the suite starts
with the first run's taint already on disk, so a session that should be on its first touch of a
classified artifact is over the accumulation threshold instead:

    test_a_direct_read_of_the_real_path_still_works   expected `ask`, got `deny`
    test_dot_dot_traversal_to_a_classified_path...    expected `ask`, got `deny`
    test_subagent_merge_actually_changes_the_parent   parent already carried `restricted`

All three passed on a clean checkout and failed on a second run — the classic order-and-history
dependence, arriving through a filesystem rather than through a fixture.

The fixture below points `$STOP_GUESSING_HOME` at a per-test temporary directory. That is the
override `paths.py` documents for exactly this ("a deployment that genuinely wants one shared
ledger... can still have it"), so no product code changes and no test assertion is weakened — each
test simply gets the clean session it always assumed it had.

Deliberately NOT done here: deleting the stale files under `./.stop-guessing/`. That directory also
holds live session state for real sessions, and this project's whole position is that evidence is
not deleted to make a number look better. Isolation makes them irrelevant; it does not destroy them.

Tests that assert the DEFAULT resolution (`tests/test_data_location.py`) already
`monkeypatch.delenv("STOP_GUESSING_HOME")` themselves, so they are unaffected by this.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolate_stop_guessing_home(tmp_path_factory, monkeypatch):
    """Give every test its own data home, inherited by subprocesses via the environment.

    `monkeypatch.setenv` writes `os.environ`, so the many tests here that drive the real CLI or the
    real hook in a subprocess get the same isolation as the in-process ones. That matters: a
    subprocess inheriting the repository's data home is precisely how the state above accumulated.
    """
    home = tmp_path_factory.mktemp("sg-home")
    monkeypatch.setenv("STOP_GUESSING_HOME", str(home))
    return home
