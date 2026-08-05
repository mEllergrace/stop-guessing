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
