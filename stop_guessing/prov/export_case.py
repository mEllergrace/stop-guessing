"""CASE / UCO JSON-LD.

CASE (Cyber-investigation Analysis Standard Expression) extends UCO and has heavy NIST
involvement. It is the only published vocabulary that separates the two things this tool records:

- **chain of custody** — who handled the artifact, when, and under what authority
- **chain of evidence** — what processes and tools acted on it

Those are different questions and most systems conflate them. Keeping them separate is why
`usnistgov/CASE-Implementation-PROV-O`'s `case_prov_check` can find a custody break at all.

Emitted as JSON-LD with CASE's own context. Not claimed to be a complete CASE bundle — it is the
custody and evidence facets of one ledger, which is what CASE tooling needs to check the chain.
"""

from __future__ import annotations

import uuid as _uuid

CASE_CONTEXT = {
    "@vocab": "https://ontology.caseontology.org/case/investigation/",
    "uco-core": "https://ontology.unifiedcyberontology.org/uco/core/",
    "uco-observable": "https://ontology.unifiedcyberontology.org/uco/observable/",
    "uco-action": "https://ontology.unifiedcyberontology.org/uco/action/",
    "uco-identity": "https://ontology.unifiedcyberontology.org/uco/identity/",
    "sg": "https://stop-guessing.dev/ns#",
    "xsd": "http://www.w3.org/2001/XMLSchema#",
}


#: Stable namespace for name-based identifiers. UUIDv5 is SHA-1 over (namespace, name), so the same
#: record always yields the same identifier — which this toolchain requires, because exports get
#: digested and pinned and a random id per run would make them non-reproducible.
_NS = _uuid.uuid5(_uuid.NAMESPACE_URL, "https://stop-guessing.dev/ns#")


def _kb(kind: str, name: str) -> str:
    """A `kb:` identifier ending in an RFC-4122 UUID, as UCO asks for (#92).

    UCO's `core:UcoThing-identifier-regex-shape` advises that identifiers end with a UUID matching
    `[0-9a-f]{8}-...-[0-5][0-9a-f]{3}-...`. Ours were content-derived strings like
    `kb:agent-stop-guessing/0.1.0`, which produced 121 Info-level results from NIST's validator — and
    also embedded a `/` in an IRI.

    `case_validate` ships `--allow-info`, and using it would have been the cheap route: the advisory
    is not a violation. It would also have been this project's own worst habit — passing a check by
    lowering what is checked. The version nibble in that regex permits `[0-5]`, so **UUIDv5
    qualifies**, and UUIDv5 is deterministic. Conformance and reproducibility turn out not to be in
    tension at all, which is usually the case when a flag looks tempting.

    The readable original is preserved on the node as `sg:localId`, so nothing is lost to opacity.
    """
    return f"kb:{kind}-{_uuid.uuid5(_NS, f'{kind}:{name}')}"


def _dt(value):
    """A typed `xsd:dateTime` literal, or absent.

    #92: `uco-action:startTime` was emitted as a bare JSON string. UCO's SHACL shape requires
    `sh:datatype xsd:dateTime`, so NIST's `case_validate` raised a DatatypeConstraintComponent
    violation for every single record — 4,488 of them across the live ledger, all one root cause.

    Returning None for a missing timestamp is deliberate: JSON-LD drops the key, which is correct.
    Emitting an empty typed literal would assert that the action happened at an unparseable time
    rather than that we do not know when it happened.
    """
    if not value:
        return None
    return {"@type": "xsd:dateTime", "@value": str(value)}


def _pred(record: dict) -> dict:
    """Delegates to the shared normaliser (#89). Kept as a name in case anything calls it."""
    from stop_guessing.prov.vocab import normalise

    return normalise(record)


def export(records: list[dict]) -> dict:
    """A CASE bundle carrying the custody and evidence facets of this ledger."""
    graph: list[dict] = []
    seen_artifacts: set[str] = set()

    for rec in records:
        p = _pred(rec)
        rid = (p.get("record") or {}).get("id") or f"seq-{rec.get('seq')}"
        actor = p.get("actor") or {}
        res = p.get("resources") or rec.get("resources") or {}

        # ── chain of custody: who held it, when, under what authority ────────
        custody = {
            "@id": _kb("custody", str(rid)),
            "sg:localId": str(rid),
            "@type": "uco-action:Action",
            "uco-core:name": "custody-transfer",
            "sg:chain": "custody",
            "uco-action:startTime": _dt((p.get("record") or {}).get("at")),
            "uco-action:performer": {
                "@id": _kb("agent", str(actor.get("agent_id", "unknown"))),
                "sg:localId": str(actor.get("agent_id", "unknown")),
                "@type": "uco-identity:Identity",
                "sg:operator": (actor.get("operator") or {}).get("identity"),
                "sg:actedOnBehalfOf":
                    (actor.get("acted_on_behalf_of") or {}).get("human_id"),
            },
            "sg:authority": {
                "posture": (p.get("authority") or {}).get("posture"),
                "capability": (p.get("authority") or {}).get("capability"),
            },
            # ISO/IEC 27037 §5.4.1: any unavoidable alteration, WITH its justification.
            "sg:alterations": p.get("alterations", []),
        }
        graph.append(custody)

        # ── chain of evidence: what process acted on it ──────────────────────
        method = (p.get("action") or {}).get("method") or {}
        graph.append({
            "@id": _kb("evidence", str(rid)),
            "sg:localId": str(rid),
            "@type": "uco-action:Action",
            "uco-core:name": (p.get("action") or {}).get("op") or rec.get("op"),
            "sg:chain": "evidence",
            "sg:method": method.get("kind"),
            "sg:tool": ((p.get("action") or {}).get("tool") or {}).get("name"),
            "sg:script": (method.get("script") or {}).get("path"),
            "uco-action:object": [
                {"@id": _kb("artifact", str(u.get("artifact_id")))}
                for u in res.get("used") or []],
            "uco-action:result": [
                {"@id": _kb("artifact", str(g.get("artifact_id")))}
                for g in res.get("generated") or []],
        })

        for ref in (res.get("used") or []) + (res.get("generated") or []):
            aid = ref.get("artifact_id")
            if not aid or aid in seen_artifacts:
                continue
            seen_artifacts.add(aid)
            facets = [{"@type": "uco-observable:FileFacet",
                       "uco-observable:filePath": ref.get("path")}]
            if ref.get("digest"):
                facets.append({
                    "@type": "uco-observable:ContentDataFacet",
                    "uco-observable:hash": [{
                        "@type": "uco-core:Hash",
                        "uco-core:hashMethod": "SHA256",
                        "uco-core:hashValue": str(ref["digest"]).removeprefix("sha256:"),
                    }]})
            graph.append({
                "@id": _kb("artifact", str(aid)),
                "sg:localId": str(aid),
                "@type": "uco-observable:ObservableObject",
                "sg:classification": ref.get("labels") or [],
                "uco-core:hasFacet": facets,
            })

    return {"@context": CASE_CONTEXT, "@graph": graph}
