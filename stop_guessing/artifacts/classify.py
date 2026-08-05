"""Classify an artifact by its identity, and a command by its shape.

Two deliberate choices:

**Contents are never read to classify.** A file named `api_keys.txt` is classified from its name.
Reading it to decide whether it is sensitive would put the sensitive thing into the process that
was trying to protect it — and in an agentic context, potentially into model context. The cost is
false positives, which is the correct direction to be wrong in.

**All matching rules apply and their labels join.** no-noodles' risk engine takes only the first
match, which is a documented limitation there (`RISK_MODEL_PLAN.md:84-87`): a later egress rule
never fires on `rm -rf | curl`. Here an artifact that is both a credential store and CSA material
carries both labels, because dropping the second obligation because a first rule matched is how a
classification silently understates what it found.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from stop_guessing.taint.labels import join
from stop_guessing.version import rules_dir

DEFAULT_RULES = rules_dir() / "classify.yaml"


@dataclass(frozen=True)
class Rule:
    id: str
    pattern: str
    labels: frozenset[str]
    reason: str

    @property
    def regex(self) -> re.Pattern:
        return _compiled(self.pattern)


@dataclass(frozen=True)
class Classification:
    labels: frozenset[str]
    matched: tuple[str, ...]
    sources: tuple[str, ...]

    @property
    def classified(self) -> bool:
        from stop_guessing.taint.labels import is_classified

        return is_classified(self.labels)

    def to_dict(self) -> dict:
        return {
            "labels": sorted(self.labels),
            "matched_rules": list(self.matched),
            "classification_source": list(self.sources),
        }


@lru_cache(maxsize=512)
def _compiled(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE)


@lru_cache(maxsize=8)
def load_rules(path: str | None = None) -> tuple[tuple[Rule, ...], tuple[Rule, ...], str]:
    """Returns (artifact rules, egress rules, ruleset digest)."""
    import yaml

    from stop_guessing.artifacts.digest import file_digest

    p = Path(path) if path else DEFAULT_RULES
    doc = yaml.safe_load(p.read_text(encoding="utf-8"))
    rules = tuple(
        Rule(r["id"], r["pattern"], frozenset(r["labels"]), r.get("reason", ""))
        for r in doc.get("rules", [])
    )
    egress = tuple(
        Rule(r["id"], r["pattern"], frozenset(), r.get("reason", ""))
        for r in doc.get("egress_patterns", [])
    )
    return rules, egress, file_digest(p) or "unknown"


def classify_path(path: str, rules_path: str | None = None) -> Classification:
    """Label an artifact from its path alone."""
    rules, _, digest = load_rules(rules_path)
    matched, sources = [], []
    label_sets = []
    for rule in rules:
        if rule.regex.search(str(path)):
            matched.append(rule.id)
            sources.append(f"rules/classify.yaml#{rule.id}")
            label_sets.append(rule.labels)
    labels = join(*label_sets) if label_sets else frozenset({"public"})
    return Classification(labels, tuple(matched), tuple(sources))


def ruleset_digest(rules_path: str | None = None) -> str:
    return load_rules(rules_path)[2]


@dataclass(frozen=True)
class EgressVerdict:
    is_egress: bool
    matched: tuple[str, ...]
    reasons: tuple[str, ...]


def classify_egress(command: str, rules_path: str | None = None) -> EgressVerdict:
    """Does this command shape send data somewhere?

    Judged on the command rather than the artifact, because by the time an artifact reaches an
    outbound call its contents are usually already in context — the question at that point is
    whether the bytes leave, not whether they were read.
    """
    _, egress, _ = load_rules(rules_path)
    matched, reasons = [], []
    for rule in egress:
        if rule.regex.search(command):
            matched.append(rule.id)
            reasons.append(rule.reason)
    return EgressVerdict(bool(matched), tuple(matched), tuple(reasons))


def paths_in(tool_name: str, tool_input: dict) -> list[str]:
    """Every filesystem path a tool call plausibly touches.

    Over-collects on purpose: a path missed here is an artifact whose custody is never recorded,
    which is a silent gap. A path collected in error is a spurious `artifact.identify` record,
    which is noise.
    """
    out: list[str] = []
    for key in ("file_path", "path", "notebook_path"):
        v = tool_input.get(key)
        if isinstance(v, str) and v:
            out.append(v)
    if tool_name == "Bash":
        cmd = tool_input.get("command", "")
        # Absolute, ~ and ./ forms.
        out.extend(re.findall(r"(?:^|[\s=\"'])((?:/|~/|\./)[\w./~@%+-]+)", cmd))
        # Fixes #22: BARE RELATIVE names were invisible, so `cat api_keys.txt` produced no
        # candidate at all and a credential file was never classified. Anything that looks like a
        # filename with an extension counts, plus redirect targets. Over-collects deliberately —
        # a missed path is a silent custody gap; a spurious one is a noisy record.
        out.extend(re.findall(r"(?:^|[\s=\"'<>|])([\w][\w.@%+-]*\.[A-Za-z][\w]{0,8})", cmd))
        out.extend(re.findall(r"[12]?>>?\s*([\w./~@%+-]+)", cmd))
    for key in ("file_paths", "paths"):
        v = tool_input.get(key)
        if isinstance(v, list):
            out.extend(x for x in v if isinstance(x, str))
    seen, uniq = set(), []
    for p in out:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq
