"""Handlers — the deterministic code that touches data so the model does not.

This is the project's thesis made operational rather than recommended. The gate used to print
"Preferred — delegate" and then proceed with the direct read, which is advice a tool has no
intention of taking; within a day that message is filtered out by everyone who sees it.

Now a classified read with a matching handler is **satisfied differently** instead of being either
blocked or waved through:

    Read /work/CSA/roster.csv
      -> handler scripts/summarise_roster.py (test passed, digest pinned)
      -> the model receives "4213 rows, 3 columns, no free-text fields"
      -> the file's contents never enter context
      -> recorded with method=delegated-script

The operation is not blocked. The *request* is answered — which is what "agentics do not handle
data, they decide how to respond to a request for data" actually means when it is built rather
than asserted.

**No handler means no substitution.** The call proceeds exactly as it would have, and is recorded.
A missing handler must never become a refusal, or this stops being an evidence tool and becomes a
permission system by the back door.

Handlers are matched by the artifact's classification and path, declared in `handlers/index.yaml`:

    handlers:
      - id: roster-summary
        match: {labels: [pii], pattern: 'roster|members'}
        script: handlers/summarise_roster.py
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

INDEX_NAME = "index.yaml"
DEFAULT_DIR = "handlers"


@dataclass(frozen=True)
class Handler:
    id: str
    script: Path
    labels: frozenset[str]
    pattern: str | None
    reason: str = ""

    def matches(self, path: str, labels: frozenset[str]) -> bool:
        if self.labels and not (self.labels & labels):
            return False
        return not (self.pattern and not re.search(self.pattern, path, re.IGNORECASE))


@dataclass
class Substitution:
    """What the model receives instead of the artifact, and the evidence for it."""

    handler_id: str
    script: str
    script_digest: str | None
    test_passed: bool
    output: str
    exit_code: int
    reason: str = ""

    @property
    def usable(self) -> bool:
        return self.test_passed and self.exit_code == 0 and bool(self.output.strip())

    def to_record(self) -> dict:
        return {
            "kind": "delegated-script",
            "script": {"id": self.handler_id, "path": self.script,
                       "digest": self.script_digest,
                       "test_result": {"passed": self.test_passed},
                       "exit_code": self.exit_code},
            "output_digest": _digest(self.output),
        }


def _digest(text: str) -> str:
    from stop_guessing.artifacts.digest import bytes_digest

    return "sha256:" + bytes_digest(text.encode())


def search_roots(cwd: str | None) -> list[Path]:
    """Where handlers may live. Project first, so a repo can ship its own."""
    roots = []
    if cwd:
        roots.append(Path(cwd) / DEFAULT_DIR)
    import os

    cfg = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude")
    roots.append(Path(cfg) / "stop-guessing" / DEFAULT_DIR)
    return roots


@lru_cache(maxsize=16)
def _load_index(root: str) -> tuple[Handler, ...]:
    import yaml

    idx = Path(root) / INDEX_NAME
    if not idx.is_file():
        return ()
    try:
        doc = yaml.safe_load(idx.read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return ()
    out = []
    for h in doc.get("handlers") or []:
        match = h.get("match") or {}
        script = Path(root) / Path(h["script"]).name if "/" not in h.get("script", "") \
            else Path(h["script"])
        if not script.is_absolute():
            script = Path(root).parent / h["script"]
        out.append(Handler(
            id=h["id"], script=script,
            labels=frozenset(match.get("labels") or []),
            pattern=match.get("pattern"),
            reason=h.get("reason", ""),
        ))
    return tuple(out)


def find(path: str, labels: frozenset[str], cwd: str | None = None) -> Handler | None:
    """The first handler that matches this artifact, or None."""
    for root in search_roots(cwd):
        for h in _load_index(str(root)):
            if h.matches(path, labels) and h.script.is_file():
                return h
    return None


def run(handler: Handler, artifact: str, *, timeout: int = 60) -> Substitution:
    """Run the handler over the artifact and bring back what the model should see.

    The full delegation sequence still applies — the paired test must pass, and the script must not
    have changed since it did. A handler that skipped that would be arbitrary code deciding what
    the model believes about a file, which is worse than reading the file.
    """
    from stop_guessing.artifacts.digest import file_digest
    from stop_guessing.delegate import Delegation, DelegationRefused, run_test
    from stop_guessing.delegate import run as run_script

    d = Delegation(handler.script.stem, handler.script,
                   handler.script.parent / f"test_{handler.script.stem}.py", handler.reason)
    digest = file_digest(handler.script)
    try:
        res = run_test(d)
    except DelegationRefused as exc:
        return Substitution(handler.id, str(handler.script), digest, False, "", 1, str(exc))
    if not res.get("passed"):
        return Substitution(handler.id, str(handler.script), digest, False, "", 1,
                            f"handler test failed: {res.get('tail', '')}")
    try:
        out = run_script(d, [artifact], timeout=timeout)
    except DelegationRefused as exc:
        return Substitution(handler.id, str(handler.script), digest, True, "", 1, str(exc))
    return Substitution(handler.id, str(handler.script), digest, True,
                        out["output"], out["exit_code"])


def substitute(path: str, labels: frozenset[str], cwd: str | None = None) -> Substitution | None:
    """Find and run a handler for this artifact. None when there is none — never a refusal."""
    h = find(path, labels, cwd)
    if h is None:
        return None
    sub = run(h, path)
    return sub if sub.usable else sub  # unusable is still reported, and still not a refusal
