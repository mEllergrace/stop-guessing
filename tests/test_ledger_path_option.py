"""`ledger --path` must reach the ledger it names.

The resolver introduced for #66 ("one resolver, and it names what it resolved")
calls itself instead of reading `args.path`:

    return Path(_path(args)) if getattr(args, "path", None) else installed_ledger()

So every `--path` invocation recursed until the interpreter gave up, and no
ledger other than the installed profile's could be verified at all. The
per-project ledgers are where the evidence lives -- one consumer's has 492
records tracked in git -- so a whole class of verification was unreachable
while the option parsed, `--help` printed it, and nothing said otherwise.

Same defect as the retract command in test_cli_dispatch: registered, and
never driven. Inspecting the parser cannot catch it; running it can.
"""

from __future__ import annotations

import json
import subprocess
import sys
from argparse import Namespace

from stop_guessing.cli.cmd_ledger import _path
from stop_guessing.version import installed_ledger


def test_the_resolver_returns_the_path_it_was_given(tmp_path) -> None:
    named = tmp_path / "custody.jsonl"
    named.write_text("")
    assert _path(Namespace(path=str(named))) == named


def test_the_resolver_falls_back_to_the_installed_ledger() -> None:
    assert _path(Namespace(path=None)) == installed_ledger()


def test_verifying_a_named_ledger_does_not_crash(tmp_path) -> None:
    """The observable failure: a RecursionError instead of a verdict."""
    named = tmp_path / "custody.jsonl"
    named.write_text(json.dumps({
        "op": "tool.result", "seq": 0, "at": "2026-09-17T00:00:00.000Z",
        "actor": "test", "prev_hash": None, "hash_alg": "sha256",
        "keyid": None, "hash": "0" * 64,
    }) + "\n")

    done = subprocess.run(
        [sys.executable, "-m", "stop_guessing.cli.main", "ledger", "verify",
         "--path", str(named), "--public"],
        capture_output=True, text=True)

    combined = done.stdout + done.stderr
    assert "RecursionError" not in combined, combined
    assert "maximum recursion depth" not in combined, combined
    # It may pass or fail on the fixture's content; it must not fail to run.
    assert "1 record" in combined or "chain" in combined.lower(), combined
