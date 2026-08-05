"""The OTel export must be OTLP, not merely span-shaped — SG-HARD-046 (#79).

Four conformance defects, each of which a Collector rejects outright:

- enums emitted as NAMES ("SPAN_KIND_INTERNAL"); OTLP/JSON uses the protobuf JSON mapping, where
  enum fields are integers;
- `traceId`/`spanId` truncated from a digest, and permitted to be `None` or short, when they must
  be exactly 32 and 16 hex characters;
- `startTimeUnixNano` hardcoded to `None`, and it is required;
- no `TracesData`/`resourceSpans`/`scopeSpans` envelope at all — a bare list, which nothing can
  ingest.

The last test is the one that matters: the output is parsed by the actual protobuf definitions,
not by assertions this repository wrote about itself.
"""

from __future__ import annotations

import pytest

from stop_guessing.prov.export_otel import export


@pytest.fixture
def records():
    return [
        {"seq": 1, "hash": "a" * 64, "at": "2026-08-05T10:00:00.000Z", "op": "artifact.read",
         "predicate": {"action": {"op": "artifact.read", "tool": {"name": "Read"},
                                  "started_at": "2026-08-05T10:00:00.000Z",
                                  "ended_at": "2026-08-05T10:00:00.041Z"},
                       "lifecycle": {"session_id": "s1"},
                       "decision": {"outcome": "allow"}}},
        {"seq": 2, "hash": "b" * 64, "at": "2026-08-05T10:00:01.000Z", "op": "artifact.egress",
         "predicate": {"action": {"op": "artifact.egress"},
                       "lifecycle": {"session_id": "s1"},
                       "decision": {"outcome": "deny"}}},
    ]


def _spans(out):
    return out["resourceSpans"][0]["scopeSpans"][0]["spans"]


def test_the_envelope_is_present(records):
    out = export(records)
    assert isinstance(out, dict), "a bare list is not OTLP"
    assert "resourceSpans" in out
    assert "scopeSpans" in out["resourceSpans"][0]
    assert out["resourceSpans"][0]["resource"]["attributes"], "resource attributes are required"


def test_enums_are_integers_not_names(records):
    for span in _spans(export(records)):
        assert isinstance(span["kind"], int), f"kind is {span['kind']!r}, must be an integer"
        assert isinstance(span["status"]["code"], int)


def test_a_denied_call_maps_to_status_error(records):
    spans = _spans(export(records))
    assert spans[0]["status"]["code"] == 1, "allow -> OK"
    assert spans[1]["status"]["code"] == 2, "deny -> ERROR"


def test_ids_have_the_exact_required_widths(records):
    for span in _spans(export(records)):
        assert len(span["traceId"]) == 32, span["traceId"]
        assert len(span["spanId"]) == 16, span["spanId"]
        int(span["traceId"], 16)   # must be hex
        int(span["spanId"], 16)


def test_ids_are_deterministic(records):
    """A provenance exporter emitting random ids would defeat its own purpose."""
    assert _spans(export(records))[0]["spanId"] == _spans(export(records))[0]["spanId"]


def test_records_in_one_session_share_a_trace(records):
    a, b = _spans(export(records))
    assert a["traceId"] == b["traceId"], "same session should be one trace"
    assert a["spanId"] != b["spanId"], "distinct records must be distinct spans"


def test_timestamps_are_populated_nanoseconds(records):
    for span in _spans(export(records)):
        assert span["startTimeUnixNano"] not in (None, "", "0")
        assert int(span["startTimeUnixNano"]) > 1_700_000_000_000_000_000
        assert int(span["endTimeUnixNano"]) >= int(span["startTimeUnixNano"])


def test_a_record_with_no_timestamps_does_not_emit_none(records):
    out = export([{"seq": 3, "hash": "c" * 64, "op": "session.open", "predicate": {}}])
    span = _spans(out)[0]
    assert span["startTimeUnixNano"] is not None
    assert len(span["traceId"]) == 32 and len(span["spanId"]) == 16


def test_it_parses_as_real_otlp_tracesdata(records):
    """Independent validation: the actual protobuf definitions, not our own assertions."""
    proto = pytest.importorskip(
        "opentelemetry.proto.trace.v1.trace_pb2",
        reason="opentelemetry-proto not installed; install it to validate OTLP conformance",
    )
    from google.protobuf.json_format import ParseDict

    msg = proto.TracesData()
    ParseDict(export(records), msg)          # raises on any non-conforming field
    spans = msg.resource_spans[0].scope_spans[0].spans
    assert len(spans) == 2
    assert spans[0].name and spans[0].start_time_unix_nano > 0
    assert spans[1].status.code == 2

    # Deliberately NOT asserting the decoded id byte-length. OTLP/JSON is an explicit EXCEPTION to
    # the standard protobuf JSON mapping for exactly these two fields: the spec requires trace_id
    # and span_id to be hex strings, while `ParseDict` applies the generic rule and decodes them as
    # base64. So a 32-character hex trace id — which is what the spec asks for — decodes to 24
    # bytes here rather than 16. The mismatch is in the validator's generic rule, not the output;
    # the hex form is asserted directly by test_ids_have_the_exact_required_widths.
