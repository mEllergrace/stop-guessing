"""Proof procedures — the only thing permitted to write `proofs:` in `docs/claims.yaml`.

A **proof** here is not a passing test. It is a procedure that exercises a claim's real surface,
whose outcome is written into this toolchain's own keyed ledger, and whose ledger record verifies
under the chain key. Test names and CI logs are supporting material.

The rule that gives this meaning: `proofs:` is never edited by hand. If a human could type a
record id into `claims.yaml`, the artifact would prove nothing except that someone typed. That is
the same failure `rockin-robin/docs/PIPELINE-CONFORMANCE-GAP.md` names — *"that is a STRING IN A
PROMPT, not conformance."*

A procedure that cannot fail is not a proof. Every procedure here must have a way of returning
``passed=False``, and the negative and adversarial procedures must actually exercise it.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from dataclasses import dataclass, field

from stop_guessing.artifacts.digest import bytes_digest


@dataclass
class ProofResult:
    """What a procedure observed. ``passed`` is the claim's verdict, not the procedure's health."""

    passed: bool
    observations: list[str] = field(default_factory=list)
    detail: str = ""
    #: Anything the procedure wants pinned into the record — digests, counts, exit codes.
    evidence: dict = field(default_factory=dict)

    def observe(self, line: str) -> None:
        self.observations.append(line)

    def fail(self, why: str) -> ProofResult:
        self.passed = False
        self.observations.append(f"FAILED: {why}")
        return self


@dataclass(frozen=True)
class Procedure:
    claim_id: str
    kind: str
    fn: Callable[[], ProofResult]
    summary: str

    def source_digest(self) -> str:
        """Digest of the procedure's own source.

        Pinned into the record so a later reader can tell whether the thing that produced this
        proof is the thing standing in the tree today. A proof whose procedure has silently
        changed is not evidence for the claim it was recorded against.
        """
        try:
            src = inspect.getsource(self.fn)
        except (OSError, TypeError):  # pragma: no cover
            return "unavailable"
        return bytes_digest(src.encode())


REGISTRY: dict[str, Procedure] = {}


def proof(claim_id: str, kind: str, summary: str):
    """Register a procedure for a claim.

    ``kind`` must match the claim's ``proof_kind`` in claims.yaml; `stop-guessing claims check`
    enforces that, so a claim declared ``adversarial`` cannot be quietly satisfied by a happy-path
    procedure.
    """

    def deco(fn: Callable[[], ProofResult]) -> Callable[[], ProofResult]:
        if claim_id in REGISTRY:
            raise ValueError(f"duplicate proof procedure for {claim_id}")
        REGISTRY[claim_id] = Procedure(claim_id, kind, fn, summary)
        return fn

    return deco


def get(claim_id: str) -> Procedure | None:
    import stop_guessing.prove.procedures  # noqa: F401  (registers on import)

    return REGISTRY.get(claim_id)


def all_procedures() -> dict[str, Procedure]:
    import stop_guessing.prove.procedures  # noqa: F401

    return dict(REGISTRY)
