"""PROV-JSON.

The W3C PROV-JSON serialisation (Member Submission, 2013). Round-trippable by the `prov` Python
library, which is what makes this worth emitting rather than a bespoke graph format.

One artifact is one `entity`, one decision is one `activity`, the agent and the human it acted for
are `agent`s joined by `actedOnBehalfOf`. Derivation edges become `wasDerivedFrom` — the relation
that carries the whole point of the tool.
"""

from __future__ import annotations

from stop_guessing.prov import vocab as v


def _pred(record: dict) -> dict:
    if "statement" in record and isinstance(record["statement"], dict):
        return record["statement"].get("predicate", record["statement"])
    return record.get("predicate", record)


def export(records: list[dict]) -> dict:
    """A PROV-JSON document for a ledger."""
    doc: dict = {
        "prefix": {"prov": v.PROV_NS, "sg": "https://stop-guessing.dev/ns#"},
        "entity": {}, "activity": {}, "agent": {},
        "used": {}, "wasGeneratedBy": {}, "wasDerivedFrom": {},
        "wasAssociatedWith": {}, "actedOnBehalfOf": {},
    }
    n = 0
    for rec in records:
        p = _pred(rec)
        rid = (p.get("record") or {}).get("id") or f"seq-{rec.get('seq')}"
        act = v.activity_id(str(rid))
        actor = p.get("actor") or {}
        agent = v.agent_id(actor.get("agent_id") or "unknown")

        doc["activity"][act] = {
            "prov:startTime": (p.get("action") or {}).get("started_at")
            or (p.get("record") or {}).get("at"),
            "sg:op": (p.get("action") or {}).get("op") or rec.get("op"),
            "sg:outcome": (p.get("decision") or {}).get("outcome") or rec.get("outcome"),
            "sg:determiningPolicy": (p.get("policy") or {}).get("determining_policy"),
        }
        doc["agent"][agent] = {"prov:type": v.SOFTWARE_AGENT,
                               "sg:agentType": actor.get("agent_type")}
        n += 1
        doc["wasAssociatedWith"][f"_:assoc{n}"] = {
            "prov:activity": act, "prov:agent": agent}

        behalf = actor.get("acted_on_behalf_of") or {}
        human = behalf.get("human_id")
        if human:
            person = v.person_id(human)
            doc["agent"][person] = {"prov:type": v.PERSON}
            doc["actedOnBehalfOf"][f"_:deleg{n}"] = {
                "prov:delegate": agent, "prov:responsible": person,
                "prov:activity": act, "sg:promptId": behalf.get("prompt_id")}

        res = p.get("resources") or rec.get("resources") or {}
        for u in res.get("used") or []:
            ent = v.entity_id(u.get("artifact_id", "unknown"))
            doc["entity"][ent] = _entity(u)
            n += 1
            doc["used"][f"_:used{n}"] = {"prov:activity": act, "prov:entity": ent,
                                         "prov:role": u.get("role", "input")}
        for g in res.get("generated") or []:
            ent = v.entity_id(g.get("artifact_id", "unknown"))
            doc["entity"][ent] = _entity(g)
            n += 1
            doc["wasGeneratedBy"][f"_:gen{n}"] = {"prov:activity": act, "prov:entity": ent}
        for d in res.get("derived_from") or []:
            n += 1
            doc["wasDerivedFrom"][f"_:der{n}"] = {
                "prov:generatedEntity": v.entity_id(d.get("generated", "unknown")),
                "prov:usedEntity": v.entity_id(d.get("source", "unknown")),
                "prov:activity": act, "sg:via": d.get("via")}
    return doc


def _entity(ref: dict) -> dict:
    return {
        "prov:type": v.ENTITY,
        "sg:path": ref.get("path"),
        "sg:digest": ref.get("digest"),
        "sg:classification": ref.get("labels") or [],
    }
