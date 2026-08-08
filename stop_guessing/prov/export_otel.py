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

from stop_guessing.version import __version__

CSA_NS = "csa.coc"


def _pred(record: dict) -> dict:
    """Delegates to the shared normaliser (#89). Kept as a name in case anything calls it."""
    from stop_guessing.prov.vocab import normalise

    return normalise(record)


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
        # #79 (SG-HARD-046). Four conformance defects, all of which a Collector rejects:
        #   - enums were emitted as NAMES; OTLP/JSON uses the protobuf JSON mapping, where enum
        #     fields are INTEGERS (SPAN_KIND_INTERNAL = 1, STATUS_CODE_OK = 1, ERROR = 2);
        #   - traceId/spanId must be exactly 32 and 16 hex characters, and could be None or short;
        #   - startTimeUnixNano was None, and it is required;
        #   - the whole thing was a bare list, with no TracesData/resourceSpans/scopeSpans
        #     envelope, so nothing could ingest it at all.
        start_ns = _nanos(action.get("started_at") or rec.get("at"))
        end_ns = _nanos(action.get("ended_at") or rec.get("at")) or start_ns
        spans.append({
            "traceId": _trace_id(life.get("transcript_digest") or life.get("session_id")
                                 or rec.get("hash")),
            "spanId": _span_id(rec.get("hash") or str(rec.get("seq"))),
            "name": attrs["gen_ai.tool.name"] or action.get("op") or "custody",
            "kind": SPAN_KIND_INTERNAL,
            "startTimeUnixNano": str(start_ns),
            "endTimeUnixNano": str(end_ns),
            "attributes": [{"key": k, "value": _val(v)}
                           for k, v in attrs.items() if v is not None],
            "status": {"code": STATUS_CODE_ERROR
                       if (decision.get("outcome") == "deny") else STATUS_CODE_OK},
        })

    # The OTLP/JSON envelope. Without it the output is span-shaped JSON, not OTLP.
    return {
        "resourceSpans": [{
            "resource": {"attributes": [
                {"key": "service.name", "value": {"stringValue": "stop-guessing"}},
                {"key": "service.version", "value": {"stringValue": __version__}},
                {"key": "telemetry.sdk.name", "value": {"stringValue": "stop-guessing"}},
                {"key": "telemetry.sdk.language", "value": {"stringValue": "python"}},
            ]},
            "scopeSpans": [{
                "scope": {"name": "stop_guessing.prov.export_otel", "version": __version__},
                "spans": spans,
            }],
        }],
    }


def _val(v):
    if isinstance(v, bool):
        return {"boolValue": v}
    if isinstance(v, int):
        return {"intValue": str(v)}
    if isinstance(v, list):
        return {"arrayValue": {"values": [_val(x) for x in v if x is not None]}}
    return {"stringValue": str(v)}


#: OTLP/JSON encodes enums as integers (protobuf JSON mapping), not as their names.
SPAN_KIND_INTERNAL = 1
STATUS_CODE_UNSET, STATUS_CODE_OK, STATUS_CODE_ERROR = 0, 1, 2

_TRACE_HEX, _SPAN_HEX = 32, 16


def _hex_id(seed, width: int) -> str:
    """A well-formed, deterministic HEX id of exactly `width` characters.

    Hex, not base64. OTLP/JSON is an explicit exception to the standard protobuf JSON mapping for
    `trace_id` and `span_id`: the spec requires case-insensitive hex strings for these two fields
    even though protobuf JSON would otherwise base64-encode a bytes field. A generic protobuf JSON
    parser therefore decodes them as base64 and reports 24 bytes for a 32-character trace id —
    that is the parser applying the generic rule, not a defect in this output.

    Trace and span ids have strict lengths, and an id that is short, empty or None is rejected by
    any conforming consumer. Derived from the record so the same record always maps to the same
    span — a provenance exporter that emitted random ids would defeat its own purpose.
    """
    from stop_guessing.artifacts.digest import bytes_digest

    material = "" if seed is None else str(seed)
    digest = bytes_digest(f"otel-id-v1:{material}".encode())
    return digest[:width].ljust(width, "0")


def _trace_id(seed) -> str:
    return _hex_id(seed, _TRACE_HEX)


def _span_id(seed) -> str:
    return _hex_id(seed, _SPAN_HEX)


def _nanos(ts: str | None) -> int:
    """ISO-8601 to Unix nanoseconds. Required by OTLP, and previously emitted as None."""
    from datetime import UTC, datetime

    if not ts:
        return 0
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return 0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return int(dt.timestamp() * 1_000_000_000)
