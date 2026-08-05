"""OpenTelemetry GenAI spans, plus the provenance attributes the spec does not have.

The `gen_ai.*` conventions moved to `open-telemetry/semantic-conventions-genai` at v1.42.0 and are
still Development stability. They model tool calls well and contain **zero** provenance
attributes: no classification, no artifact identity, no derivation edge. That gap is the reason
this project exists, so the export emits valid GenAI spans and adds a `csa.coc.*` namespace for
what is missing, rather than overloading an existing attribute with a different meaning.

Pre-1.0 status is an advantage here: a CSA-authored provenance attribute group is a plausible
upstream contribution, and namespacing it now is what makes that possible later.
"""

from __future__ import annotations

CSA_NS = "csa.coc"


def _pred(record: dict) -> dict:
    if "statement" in record and isinstance(record["statement"], dict):
        return record["statement"].get("predicate", record["statement"])
    return record.get("predicate", record)


def export(records: list[dict]) -> list[dict]:
    """OTLP-shaped spans, one per custody record."""
    spans = []
    for rec in records:
        p = _pred(rec)
        action = p.get("action") or {}
        gen_ai = action.get("gen_ai") or {}
        actor = p.get("actor") or {}
        life = p.get("lifecycle") or {}
        decision = p.get("decision") or {}
        res = p.get("resources") or rec.get("resources") or {}
        verif = p.get("verification") or {}

        attrs = {
            # OTel GenAI semantic conventions, as specified.
            "gen_ai.operation.name": gen_ai.get("operation_name", "execute_tool"),
            "gen_ai.tool.name": gen_ai.get("tool_name") or (action.get("tool") or {}).get("name"),
            "gen_ai.tool.type": gen_ai.get("tool_type", "function"),
            "gen_ai.tool.call.id": gen_ai.get("tool_call_id") or actor.get("runtime_action_id"),
            "gen_ai.agent.id": actor.get("agent_id"),
            "gen_ai.conversation.id": life.get("session_id"),
            # Everything below is ours, namespaced, because the spec has no provenance attributes.
            f"{CSA_NS}.op": action.get("op") or rec.get("op"),
            f"{CSA_NS}.posture": (p.get("authority") or {}).get("posture"),
            f"{CSA_NS}.decision.outcome": decision.get("outcome") or rec.get("outcome"),
            f"{CSA_NS}.decision.policy": (p.get("policy") or {}).get("determining_policy"),
            f"{CSA_NS}.taint.labels": (decision.get("basis") or {}).get("taint_labels") or [],
            f"{CSA_NS}.taint.depth": (decision.get("basis") or {}).get("taint_depth"),
            f"{CSA_NS}.custody.digest": (decision.get("basis") or {}).get(
                "session_custody_digest"),
            f"{CSA_NS}.artifacts.used": [u.get("artifact_id") for u in res.get("used") or []],
            f"{CSA_NS}.artifacts.generated": [
                g.get("artifact_id") for g in res.get("generated") or []],
            f"{CSA_NS}.derivation.edges": [
                f"{d.get('generated')}<-{d.get('source')}" for d in res.get("derived_from") or []],
            f"{CSA_NS}.verification.strength": verif.get("strength"),
            f"{CSA_NS}.verification.isolation_tier": (verif.get("recorder") or {}).get(
                "isolation_tier"),
            f"{CSA_NS}.record.seq": rec.get("seq"),
            f"{CSA_NS}.record.hash": rec.get("hash"),
        }
        spans.append({
            "name": attrs["gen_ai.tool.name"] or action.get("op") or "custody",
            "kind": "SPAN_KIND_INTERNAL",
            "traceId": (life.get("transcript_digest") or "")[:32] or None,
            "spanId": (rec.get("hash") or "")[:16] or None,
            "startTimeUnixNano": None,
            "attributes": [{"key": k, "value": _val(v)}
                           for k, v in attrs.items() if v is not None],
            "status": {"code": "STATUS_CODE_ERROR"
                       if (decision.get("outcome") == "deny") else "STATUS_CODE_OK"},
        })
    return spans


def _val(v):
    if isinstance(v, bool):
        return {"boolValue": v}
    if isinstance(v, int):
        return {"intValue": str(v)}
    if isinstance(v, list):
        return {"arrayValue": {"values": [_val(x) for x in v if x is not None]}}
    return {"stringValue": str(v)}
