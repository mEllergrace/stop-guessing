"""Every registered subcommand must actually dispatch.

`stop-guessing retract` was registered with `set_defaults(func=...)` while `main()` dispatches on
`args.fn`. The parser accepted the command and `--help` printed correctly, so it looked present in
every way a reader would check — and any real invocation died with
`AttributeError: 'Namespace' object has no attribute 'fn'`. It was only caught by a test that ran it.

That is the same defect as a hook that is registered and never executed, and as a claim that
declares a surface nobody drives. Inspecting the parser is the cheap general guard: it walks every
subparser the CLI builds and asserts each terminal command carries a callable under the key the
dispatcher reads.
"""

from __future__ import annotations

import argparse
import subprocess
import sys

from stop_guessing.cli.main import build_parser
from stop_guessing.version import repo_root

DISPATCH_KEY = "fn"


def _subparser_actions(parser):
    return [a for a in parser._actions if isinstance(a, argparse._SubParsersAction)]


def _walk(parser, path=()):
    """Yield (path, parser) for every terminal command — one with no subparsers of its own."""
    subs = _subparser_actions(parser)
    if not subs:
        yield path, parser
        return
    for action in subs:
        for name, sub in action.choices.items():
            yield from _walk(sub, (*path, name))


def test_the_dispatcher_reads_the_key_this_test_checks():
    """Guard the guard: if main() ever dispatches on a different attribute, fail here."""
    src = (repo_root() / "stop_guessing/cli/main.py").read_text(encoding="utf-8")
    assert f"args.{DISPATCH_KEY}(args)" in src, (
        f"main() no longer dispatches on args.{DISPATCH_KEY}; this test is checking the wrong key")


def test_every_terminal_subcommand_has_a_callable_handler():
    parser = build_parser()
    broken = []
    for path, sub in _walk(parser):
        if not path:
            continue
        handler = sub.get_default(DISPATCH_KEY)
        if not callable(handler):
            broken.append((" ".join(path), sub.get_default("func")))
    assert not broken, (
        "these subcommands parse but cannot run — "
        f"registered under the wrong key or not at all: {broken}")


def test_no_subcommand_registers_a_handler_under_a_key_nobody_reads():
    """The specific slip: `func=` instead of `fn=`. It fails silently until someone runs it."""
    parser = build_parser()
    stray = [" ".join(path) for path, sub in _walk(parser)
             if path and callable(sub.get_default("func"))
             and not callable(sub.get_default(DISPATCH_KEY))]
    assert not stray, f"handler registered under `func=`, which main() never reads: {stray}"


def test_the_new_surfaces_are_reachable_from_the_real_entry_point():
    """Not the parser — the installed console script, run as a user would run it."""
    for argv in (["retract", "--help"], ["record", "emit", "--help"], ["demo", "--help"]):
        res = subprocess.run(  # noqa: S603
            [sys.executable, "-m", "stop_guessing.cli.main", *argv],
            capture_output=True, text=True, cwd=str(repo_root()), timeout=300,
            stdin=subprocess.DEVNULL)
        assert res.returncode == 0, f"{argv} failed: {res.stderr[-300:]}"
        assert "usage:" in res.stdout


def test_the_walker_actually_detects_a_misregistered_command():
    """The control. A guard that cannot fail is decoration.

    Builds the exact mistake — `set_defaults(func=...)` on a real subparser — and requires the
    walker to find it. Without this, the three tests above would pass just as happily against a
    walker that yields nothing.
    """
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")
    good = sub.add_parser("good")
    good.set_defaults(fn=lambda a: 0)
    bad = sub.add_parser("bad")
    bad.set_defaults(func=lambda a: 0)          # the slip
    worse = sub.add_parser("worse")             # no handler at all
    assert worse is not None

    found = {" ".join(p) for p, s in _walk(parser) if p and not callable(s.get_default("fn"))}
    assert found == {"bad", "worse"}, f"the walker missed a broken command: {found}"


def test_the_walker_descends_into_nested_subcommands():
    """`record emit` and `caiq fill` are two levels deep; a shallow walk would skip them."""
    parser = build_parser()
    paths = {" ".join(p) for p, _ in _walk(parser) if p}
    assert "record emit" in paths, "the walker does not reach nested subcommands"
    assert "claims check" in paths


# ── a `def` below `if __name__ == "__main__"` does not exist when the hook runs ──


def test_no_cli_module_defines_anything_after_its_main_block():
    """`hook_post.py` had its `__main__` block at line 136 and three `def`s after it.

    Importing the module defined everything, so every test that imported it passed. Running it as a
    script — which is exactly how the PostToolUse hook runs it — called `main()` before the
    interpreter had reached those `def`s, and the recorder raised
    `NameError: name '_content_binding' is not defined` on every single tool call and failed open.

    It was invisible in all the usual ways: the module imports cleanly, `doctor` reported the ledger
    "intact and keyed" because the chain of crash records was itself intact, and 200+ consecutive
    `recorder.selfcheck` entries accumulated without one custody decision among them. A recorder
    that records nothing while looking installed is the worst failure this project can have, so the
    shape that caused it is checked structurally rather than trusted to review.
    """
    import ast

    from stop_guessing.version import repo_root

    offenders = []
    for path in sorted((repo_root() / "stop_guessing" / "cli").glob("*.py")):
        body = ast.parse(path.read_text(encoding="utf-8")).body
        guard = next((i for i, n in enumerate(body)
                      if isinstance(n, ast.If) and "__main__" in ast.unparse(n.test)), None)
        if guard is None:
            continue
        for node in body[guard + 1:]:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                offenders.append(f"{path.name}: {node.name} (line {node.lineno}) is defined after "
                                 f"the __main__ block (line {body[guard].lineno})")
    assert not offenders, (
        "these names do not exist when the module is run as a script, which is how the hooks run "
        "it:\n" + "\n".join(offenders))
