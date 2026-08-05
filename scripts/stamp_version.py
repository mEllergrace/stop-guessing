#!/usr/bin/env python3
# build-ok: searched /Users/isme/Software/repo-hygiene/checks/stale_docs.py — find_version_drift
# DETECTS drift and deliberately writes nothing (the whole package is read-only detectors), so it
# reports the problem this fixes rather than fixing it; this calls it for --check. Also searched
# stop_guessing/version.py (reads VERSION, does not propagate it) and scripts/ (attest_guard.py,
# hygiene_sweep.py — neither touches manifests). IMPLEMENTATION_PLAN.md §13 specifies exactly this
# script and it was never written, which is how three manifests came to declare a stale version.
"""One version, stamped everywhere it is declared.

    scripts/stamp_version.py            # stamp every manifest from VERSION
    scripts/stamp_version.py --check    # report drift, write nothing (for CI)

The plan named this failure in advance — rich-text drifted to `plugin.json` 0.2.14 against
`manifest.yaml` 0.3.0 — and said "do not repeat that". It got repeated on the very next bump,
because manual stamping updates the files you remember and this repo declares its version in five
places, two of them four directories deep in the Codex mirror.

Detection already exists upstream in repo-hygiene and is not duplicated here; `--check` calls it.
What did not exist was anything that *writes*.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

#: Files whose "version" key is the package version. Globs, so a new plugin mirror is picked up
#: without editing this list — the previous failure was a hardcoded list going out of date.
MANIFEST_GLOBS = (
    ".claude-plugin/marketplace.json",
    ".claude-plugin/**/plugin.json",
    ".agents/**/marketplace.json",
    ".agents/**/plugin.json",
    "**/.codex-plugin/plugin.json",
)

PYPROJECT_RE = re.compile(r'(?m)^(version\s*=\s*)"[^"]*"')
#: A bare `0.3.0` in prose is ambiguous; a version badge or explicit declaration is not.
MARKDOWN_RE = re.compile(r"(?m)^(\*{0,2}[Vv]ersion\*{0,2}[:\s|]+)`?v?\d+\.\d+\.\d+`?")


def read_version(repo: Path = REPO) -> str:
    return (repo / "VERSION").read_text(encoding="utf-8").strip()


def _manifest_paths(repo: Path) -> list[Path]:
    seen: dict[Path, None] = {}
    for pattern in MANIFEST_GLOBS:
        for p in repo.glob(pattern):
            if p.is_file():
                seen.setdefault(p.resolve(), None)
    return sorted(seen)


def declared_versions(repo: Path = REPO) -> dict[str, str]:
    """Every file that declares a version, and what it currently says."""
    out: dict[str, str] = {}
    for p in _manifest_paths(repo):
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(doc, dict) and "version" in doc:
            out[str(p.relative_to(repo))] = str(doc["version"])

    pyproject = repo / "pyproject.toml"
    if pyproject.is_file():
        m = re.search(r'(?m)^version\s*=\s*"([^"]*)"', pyproject.read_text(encoding="utf-8"))
        if m:
            out["pyproject.toml"] = m.group(1)

    readme = repo / "README.md"
    if readme.is_file():
        m = MARKDOWN_RE.search(readme.read_text(encoding="utf-8"))
        if m:
            out["README.md"] = m.group(0)
    return out


def stamp(repo: Path = REPO, version: str | None = None, check_only: bool = False) -> list[str]:
    """Write ``version`` into every declaring file. Returns what changed (or would change).

    Only the version key is touched — the file is re-serialised from its own parsed content with
    its own indentation, so hand-authored keys, ordering and comments in prose files survive.
    """
    version = version or read_version(repo)
    changed: list[str] = []

    for p in _manifest_paths(repo):
        try:
            raw = p.read_text(encoding="utf-8")
            doc = json.loads(raw)
        except (OSError, ValueError):
            continue
        if not isinstance(doc, dict):
            continue
        rel = p.relative_to(repo)
        dirty = False

        if doc.get("version") not in (None, version):
            changed.append(f"{rel}: {doc['version']} -> {version}")
            doc["version"] = version
            dirty = True

        # A marketplace manifest declares no version of its own — each entry in `plugins[]` carries
        # one. Stamping only the top level left .agents/plugins/marketplace.json at 0.3.0 while
        # this script reported "all declared versions agree", which is worse than not checking.
        for entry in doc.get("plugins") or []:
            if isinstance(entry, dict) and entry.get("version") not in (None, version):
                changed.append(f"{rel}[{entry.get('name', '?')}]: {entry['version']} -> {version}")
                entry["version"] = version
                dirty = True

        if dirty and not check_only:
            trailing = "\n" if raw.endswith("\n") else ""
            p.write_text(json.dumps(doc, indent=2) + trailing, encoding="utf-8")

    # docs/claims.yaml carries meta.version, and a test asserts it matches. It is the claims
    # table's own declaration of which build it describes, so it is a real version site.
    claims = repo / "docs" / "claims.yaml"
    if claims.is_file():
        raw = claims.read_text(encoding="utf-8")
        m = re.search(r"(?m)^(\s+version:\s*)(\S+)$", raw)
        if m and m.group(2) != version:
            changed.append(f"docs/claims.yaml: {m.group(2)} -> {version}")
            if not check_only:
                claims.write_text(raw[:m.start()] + m.group(1) + version + raw[m.end():],
                                  encoding="utf-8")

    pyproject = repo / "pyproject.toml"
    if pyproject.is_file():
        raw = pyproject.read_text(encoding="utf-8")
        m = re.search(r'(?m)^version\s*=\s*"([^"]*)"', raw)
        if m and m.group(1) != version:
            changed.append(f"pyproject.toml: {m.group(1)} -> {version}")
            if not check_only:
                pyproject.write_text(PYPROJECT_RE.sub(rf'\1"{version}"', raw, count=1),
                                     encoding="utf-8")

    readme = repo / "README.md"
    if readme.is_file():
        raw = readme.read_text(encoding="utf-8")
        m = MARKDOWN_RE.search(raw)
        if m and version not in m.group(0):
            changed.append(f"README.md: {m.group(0).strip()} -> {version}")
            if not check_only:
                new = MARKDOWN_RE.sub(lambda mm: f"{mm.group(1)}{version}", raw, count=1)
                readme.write_text(new, encoding="utf-8")

    return changed


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true", help="report drift, write nothing")
    ap.add_argument("--repo", default=str(REPO))
    args = ap.parse_args(argv)

    repo = Path(args.repo)
    version = read_version(repo)
    changed = stamp(repo, version, check_only=args.check)

    if not changed:
        print(f"all declared versions agree with VERSION ({version})")
        return 0
    verb = "would stamp" if args.check else "stamped"
    print(f"{verb} {len(changed)} file(s) to {version}:")
    for c in changed:
        print(f"  {c}")
    return 1 if args.check else 0


if __name__ == "__main__":
    raise SystemExit(main())
