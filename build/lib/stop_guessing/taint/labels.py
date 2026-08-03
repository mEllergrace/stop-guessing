"""The label lattice.

Sensitivity is ordered: ``public < internal < confidential < restricted``. Flags like ``pii`` and
``credential`` are orthogonal — a public dataset can still carry PII, and treating them as one
scale would let a low sensitivity silently erase a regulatory obligation.

The join is what makes derivation meaningful: an output carries the join of everything that went
into it. That is monotone within a session by construction. Labels come off only through an
explicit `custody.declassify` naming a human authorizer and a justification, which is itself
recorded as an ISO 27037 alteration — because a label that can quietly disappear is not a label.
"""

from __future__ import annotations

SENSITIVITY = ("public", "internal", "confidential", "restricted")
FLAGS = frozenset({"pii", "credential", "csa-material", "regulated"})

RANK = {name: i for i, name in enumerate(SENSITIVITY)}


def is_sensitivity(label: str) -> bool:
    return label in RANK


def sensitivity_of(labels: frozenset[str] | set[str]) -> str:
    """The highest sensitivity present, or ``public`` when none is."""
    present = [x for x in labels if is_sensitivity(x)]
    return max(present, key=lambda x: RANK[x]) if present else "public"


def join(*label_sets: frozenset[str] | set[str] | None) -> frozenset[str]:
    """Least upper bound: the highest sensitivity, plus the union of all flags."""
    flags: set[str] = set()
    sens = "public"
    for s in label_sets:
        if not s:
            continue
        for label in s:
            if is_sensitivity(label):
                if RANK[label] > RANK[sens]:
                    sens = label
            else:
                flags.add(label)
    return frozenset({sens, *flags})


def dominates(a: frozenset[str], b: frozenset[str]) -> bool:
    """Does ``a`` carry at least as much obligation as ``b``?"""
    a_flags = {x for x in a if not is_sensitivity(x)}
    b_flags = {x for x in b if not is_sensitivity(x)}
    return RANK[sensitivity_of(a)] >= RANK[sensitivity_of(b)] and b_flags <= a_flags


def is_classified(labels: frozenset[str]) -> bool:
    """Anything above `internal`, or carrying any flag, needs custody handling."""
    return RANK[sensitivity_of(labels)] >= RANK["confidential"] or bool(
        {x for x in labels if not is_sensitivity(x)}
    )


def describe(labels: frozenset[str]) -> str:
    ordered = sorted(labels, key=lambda x: (not is_sensitivity(x), x))
    return ",".join(ordered)
