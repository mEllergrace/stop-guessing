"""Session custody state — the thing no other tool feeds back into the decision.

Every agent DLP hook in the wild is a regex fired independently per call. The risk that actually
materialises in an agentic loop is *accumulation*: twelve individually-innocuous reads composing
into a restricted dataset, then one egress. Per-call matching cannot see that by construction,
because each call looks fine.

So state accumulates across a session and is passed to the policy engine as `context`. The same
`curl` that was allowed at turn 3 is denied at turn 40, and the denial names the artifacts that
changed the answer.

**The ledger is authoritative.** State is rebuilt by replaying records, never read back from a
transcript the agent could influence. `rebuild()` is what makes the state survive compaction, and
`digest` is what proves the rebuild reproduced it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from stop_guessing.artifacts.digest import bytes_digest
from stop_guessing.taint.labels import describe, is_classified, join, sensitivity_of


@dataclass
class ArtifactRef:
    artifact_id: str
    path: str
    digest: str | None
    labels: frozenset[str]

    def to_dict(self) -> dict:
        return {"artifact_id": self.artifact_id, "path": self.path,
                "digest": self.digest, "labels": sorted(self.labels)}


@dataclass
class SessionCustodyState:
    """What this session has touched, and what that makes the next call."""

    session_id: str
    labels: frozenset[str] = field(default_factory=lambda: frozenset({"public"}))
    sources: dict[str, ArtifactRef] = field(default_factory=dict)
    touched: int = 0
    since_last_egress: int = 0
    compaction_generation: int = 0
    edges: list[tuple[str, str, str]] = field(default_factory=list)

    # ── accumulation ────────────────────────────────────────────────────────

    def touch(self, ref: ArtifactRef) -> None:
        """Record a touch. Monotone: labels only ever go up within a session."""
        self.touched += 1
        self.since_last_egress += 1
        if is_classified(ref.labels):
            self.sources[ref.artifact_id] = ref
        self.labels = join(self.labels, ref.labels)

    def derive(self, output: ArtifactRef, inputs: list[ArtifactRef], via: str) -> ArtifactRef:
        """An output carries the join of its inputs. This is what makes lineage mean anything."""
        output.labels = join(output.labels, *[i.labels for i in inputs])
        for i in inputs:
            self.edges.append((output.artifact_id, i.artifact_id, via))
        self.touch(output)
        return output

    def egress(self) -> None:
        self.since_last_egress = 0

    def declassify(self, artifact_id: str) -> None:
        """Drop one artifact's contribution and recompute from what remains.

        Only ever called behind an explicit `custody.declassify` naming a human authorizer — a
        label that can quietly disappear is not a label.
        """
        self.sources.pop(artifact_id, None)
        self.labels = join(frozenset({"public"}), *[r.labels for r in self.sources.values()])

    # ── the decision inputs ─────────────────────────────────────────────────

    @property
    def depth(self) -> int:
        """Distinct classified artifacts touched — the accumulation counter."""
        return len(self.sources)

    @property
    def restricted_touched(self) -> int:
        return sum(1 for r in self.sources.values()
                   if sensitivity_of(r.labels) == "restricted")

    @property
    def graph_digest(self) -> str:
        return bytes_digest(json.dumps(sorted(self.edges), separators=(",", ":")).encode())

    @property
    def digest(self) -> str:
        """Digest of the whole state. Goes into every decision's basis, and is what a rebuild
        must reproduce exactly.

        Fixes #14. This previously hashed `sorted(self.sources)` — the dict KEYS — and omitted
        `compaction_generation` entirely, so it was not a digest of the whole state as documented.
        Two sessions that had touched the same artifact ids with different paths, content digests
        or labels produced an identical digest, and a compaction boundary left no trace in it.
        """
        body = {
            "session_id": self.session_id,
            "labels": sorted(self.labels),
            "sources": [self.sources[k].to_dict() for k in sorted(self.sources)],
            "touched": self.touched,
            "since_last_egress": self.since_last_egress,
            "compaction_generation": self.compaction_generation,
            "edges": sorted(self.edges),
        }
        return bytes_digest(json.dumps(body, sort_keys=True, separators=(",", ":")).encode())

    def context(self, *, posture: str, call: dict, artifact: dict | None = None) -> dict:
        """The Cedar-shaped `context` the PDP evaluates against."""
        return {
            "posture": posture,
            "session": {
                "taint": sorted(self.labels),
                "taint_depth": self.depth,
                "artifacts_touched": self.touched,
                "restricted_touched": self.restricted_touched,
                "since_last_egress": self.since_last_egress,
                "custody_digest": self.digest,
                "compaction_generation": self.compaction_generation,
            },
            "call": call,
            "artifact": artifact or {},
        }

    def summary(self) -> str:
        return (f"session {self.session_id}: {describe(self.labels)} "
                f"from {self.depth} classified artifact(s), {self.touched} touch(es)")


def rebuild(records: list[dict], session_id: str) -> SessionCustodyState:
    """Replay the ledger into state.

    The ledger is the source of truth and the transcript is not consulted, so a compaction that
    rewrites the conversation cannot rewrite what was touched.
    """
    state = SessionCustodyState(session_id)
    # (runtime_action_id, op) pairs already replayed. One tool call produces a decision record and
    # a result record describing the SAME effect; counting both double-counts the artifact.
    seen_effects: set[tuple] = set()
    for r in records:
        if "statement" in r and isinstance(r["statement"], dict):
            pred = r["statement"].get("predicate", r["statement"])
        else:
            pred = r.get("predicate", r)
        # Accept BOTH record shapes. The full §7 predicate nests session_id under `lifecycle` and
        # op under `action`; the hook writes them flat. This mismatch silently made every rebuild
        # return an EMPTY state, so the ledger-authoritative path reset taint on every call — a
        # worse failure than the cache it replaced, and invisible to any unit test that built its
        # own records. Found end-to-end.
        sid = _dig(pred, "lifecycle", "session_id")
        if sid is None:
            sid = pred.get("session_id")
        if sid != session_id:
            continue
        op = _dig(pred, "action", "op") or pred.get("op") or r.get("op")
        used = (_dig(pred, "resources", "used") or r.get("resources", {}).get("used") or [])
        generated = (_dig(pred, "resources", "generated")
                     or r.get("resources", {}).get("generated") or [])
        derived = (_dig(pred, "resources", "derived_from") or [])

        # #58 (SG-HARD-025). Three ways replay diverged from live state, all of which inflate it:
        #
        #   - `egress()` fired for ANY artifact.egress record, including ones that were DENIED.
        #     Replaying a blocked egress as though it happened resets since_last_egress and makes
        #     the rebuilt state disagree with the live one — and the ledger is authoritative, so
        #     the wrong state wins.
        #   - a read appears in both the PreToolUse decision and the PostToolUse result, so the
        #     same artifact was counted twice.
        #   - only `generated[0]` was used for a derivation, silently dropping every other output.
        outcome = (_dig(pred, "decision", "outcome") or pred.get("outcome")
                   or r.get("outcome"))
        # Only a DENY is certainly not effected. An `ask` means the operator was asked, and under
        # `steer` every first touch of a classified artifact is an ask — treating those as
        # non-events stopped taint accumulating entirely, which CLAIM-07's cross-process proof
        # caught immediately. An ask the operator refused will over-count taint, and that is the
        # correct direction to be wrong in: more taint denies more egress.
        effected = outcome != "deny"

        idem = (_dig(pred, "actor", "runtime_action_id") or pred.get("runtime_action_id")
                or _dig(pred, "action", "tool", "call_id"))
        if idem is not None:
            if (idem, op) in seen_effects:
                continue                              # the paired Pre/Post record for one call
            seen_effects.add((idem, op))

        if not effected:
            continue

        if op == "artifact.derive" and generated:
            inputs = [_ref(u) for u in used]
            via = derived[0].get("via", "unknown") if derived else "unknown"
            for g in generated:                        # every output, not just the first
                state.derive(_ref(g), inputs, via)
        else:
            for u in used:
                state.touch(_ref(u))
            for g in generated:
                state.touch(_ref(g))
        if op == "artifact.egress":
            state.egress()
        if op == "custody.checkpoint":
            state.compaction_generation += 1
        if op == "custody.declassify":
            target = _dig(pred, "decision", "basis", "declassified_artifact")
            if target:
                state.declassify(target)
    return state


def _ref(d: dict) -> ArtifactRef:
    return ArtifactRef(
        artifact_id=d.get("artifact_id", "unknown"),
        path=d.get("path", ""),
        digest=d.get("digest"),
        labels=frozenset(d.get("labels") or {"public"}),
    )


def _dig(obj, *path):
    cur = obj
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur
