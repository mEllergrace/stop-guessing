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

CASE_CONTEXT = {
    "@vocab": "https://ontology.caseontology.org/case/investigation/",
    "uco-core": "https://ontology.unifiedcyberontology.org/uco/core/",
    "uco-observable": "https://ontology.unifiedcyberontology.org/uco/observable/",
    "uco-action": "https://ontology.unifiedcyberontology.org/uco/action/",
    "uco-identity": "https://ontology.unifiedcyberontology.org/uco/identity/",
    "sg": "https://stop-guessing.dev/ns#",
}


def _pred(record: dict) -> dict:
    if "statement" in record and isinstance(record["statement"], dict):
        return record["statement"].get("predicate", record["statement"])
    return record.get("predicate", record)


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
            "@id": f"kb:custody-{rid}",
            "@type": "uco-action:Action",
            "uco-core:name": "custody-transfer",
            "sg:chain": "custody",
            "uco-action:startTime": (p.get("record") or {}).get("at"),
            "uco-action:performer": {
                "@id": f"kb:agent-{actor.get('agent_id', 'unknown')}",
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
            "@id": f"kb:evidence-{rid}",
            "@type": "uco-action:Action",
            "uco-core:name": (p.get("action") or {}).get("op") or rec.get("op"),
            "sg:chain": "evidence",
            "sg:method": method.get("kind"),
            "sg:tool": ((p.get("action") or {}).get("tool") or {}).get("name"),
            "sg:script": (method.get("script") or {}).get("path"),
            "uco-action:object": [
                {"@id": f"kb:artifact-{u.get('artifact_id')}"} for u in res.get("used") or []],
            "uco-action:result": [
                {"@id": f"kb:artifact-{g.get('artifact_id')}"}
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
                "@id": f"kb:artifact-{aid}",
                "@type": "uco-observable:ObservableObject",
                "sg:classification": ref.get("labels") or [],
                "uco-core:hasFacet": facets,
            })

    return {"@context": CASE_CONTEXT, "@graph": graph}
