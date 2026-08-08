"""W3C PROV vocabulary, used as the internal model rather than bolted on at export.

PROV-DM has been a W3C Recommendation since 2013 and has not moved, which for a provenance
vocabulary is a feature: `Entity` / `Activity` / `Agent` plus `used` / `wasGeneratedBy` /
`wasDerivedFrom` / `wasAssociatedWith` / `actedOnBehalfOf` says everything a custody record needs
and nothing it does not.

`actedOnBehalfOf` is the one worth naming. It is the delegation edge — *this software agent acted
for that person* — and it is exactly what CSA's draft `IAM-AG-03` asks for and what no agent
telemetry format has. It is why the record carries `acted_on_behalf_of` rather than a flat
`user` field.

Kept here as constants rather than strings scattered through the exporters, so a typo is an
ImportError rather than a silently malformed graph.
"""

from __future__ import annotations

PROV_NS = "http://www.w3.org/ns/prov#"

# Types
ENTITY = "prov:Entity"
ACTIVITY = "prov:Activity"
AGENT = "prov:Agent"
SOFTWARE_AGENT = "prov:SoftwareAgent"
PERSON = "prov:Person"
ORGANIZATION = "prov:Organization"

# Relations
USED = "prov:used"
WAS_GENERATED_BY = "prov:wasGeneratedBy"
WAS_DERIVED_FROM = "prov:wasDerivedFrom"
WAS_ASSOCIATED_WITH = "prov:wasAssociatedWith"
WAS_ATTRIBUTED_TO = "prov:wasAttributedTo"
ACTED_ON_BEHALF_OF = "prov:actedOnBehalfOf"
WAS_INFORMED_BY = "prov:wasInformedBy"

# Qualified forms, which carry role and time on the edge itself
USAGE = "prov:Usage"
GENERATION = "prov:Generation"
ASSOCIATION = "prov:Association"
DELEGATION = "prov:Delegation"

#: Every relation this package emits. Anything outside it is a bug, not an extension.
RELATIONS = frozenset({
    USED, WAS_GENERATED_BY, WAS_DERIVED_FROM, WAS_ASSOCIATED_WITH,
    WAS_ATTRIBUTED_TO, ACTED_ON_BEHALF_OF, WAS_INFORMED_BY,
})


def entity_id(artifact_id: str) -> str:
    return f"sg:artifact/{artifact_id}"


def activity_id(record_id: str) -> str:
    return f"sg:activity/{record_id}"


def agent_id(spiffe_or_name: str) -> str:
    return f"sg:agent/{spiffe_or_name}"


def person_id(human: str) -> str:
    return f"sg:person/{human}"


# ── record-shape normalisation (#89) ─────────────────────────────────────────
#
# Two record shapes exist in the ledger and the exporters only ever handled one.
#
#   nested   the gate's CustodyRecord predicate: `actor` is an object carrying agent_id, operator
#            and acted_on_behalf_of, and the eight regimes are present.
#   flat     what `prove`, `hook_lifecycle` and `segments` write: a plain event whose `actor` is a
#            STRING like "stop-guessing/0.5.3", with no regimes at all.
#
# Every exporter did `p.get("actor").get("agent_id")`, which raises `AttributeError` on the flat
# shape. 1,493 of the live records are flat, so PROV, CASE/UCO and OTLP export all crashed against
# the real ledger while passing on hand-built fixtures — the export CLI exited 1 for all three
# formats. See issue #89.
#
# The rule applied here: a flat record genuinely carries LESS information. There is no operator
# identity and no delegation edge to report. So those keys are ABSENT rather than present-and-empty.
# Filling them with "" or "unknown" would manufacture an operator who never existed, which is a
# worse failure than the crash — an export that invents a custodian is not a custody record.


def normalise(record: dict) -> dict:
    """Return the predicate for either record shape, with `actor` always an object.

    Absent regimes stay absent. `actor.agent_id` is always present because every record has an
    actor of some kind, and the exporters need something to hang an identity on.
    """
    inner = record
    if isinstance(record.get("statement"), dict):
        inner = record["statement"].get("predicate", record["statement"])
    elif isinstance(record.get("predicate"), dict):
        inner = record["predicate"]

    if not isinstance(inner, dict):
        return {"actor": {"agent_id": "unknown"}}

    actor = inner.get("actor")
    if isinstance(actor, dict):
        return inner

    out = dict(inner)
    # A flat record's `actor` is the software agent that wrote it. Recorded as a prov:SoftwareAgent
    # with no operator and no delegation, because it genuinely has neither.
    out["actor"] = {
        "prov_type": "prov:SoftwareAgent",
        "agent_id": str(actor) if actor else "unknown",
        "agent_type": "recorder",
    }
    # Lift the flat timestamp into the `record` regime so exporters find a time where they expect it.
    rec = out.get("record")
    if not isinstance(rec, dict):
        rec = {}
    rec.setdefault("id", inner.get("id") or f"seq-{inner.get('seq')}")
    rec.setdefault("at", inner.get("at"))
    if inner.get("seq") is not None:
        rec.setdefault("seq", inner["seq"])
    for k in ("hash", "prev_hash", "hash_alg"):
        if inner.get(k) is not None:
            rec.setdefault(k, inner[k])
    out["record"] = rec

    if inner.get("op") and not isinstance(out.get("action"), dict):
        out["action"] = {"prov_type": "prov:Activity", "op": inner["op"]}
    # `known_gaps` and `alterations` are Tier-A assertions and must survive normalisation verbatim:
    # an exporter that dropped them would turn "nothing was altered" into "nobody looked".
    for k in ("known_gaps", "alterations"):
        if k in inner:
            out[k] = inner[k]
    return out
