import copy
import json
from pathlib import Path
from soc_assistant.ingest import import_bytes
from soc_assistant.correlate import build_cases
from soc_assistant.config import Limits

ROOT = Path(__file__).resolve().parents[1]

def raw():
    return json.loads((ROOT / "examples/demo.jsonl").read_text().splitlines()[0])

def load(rows, limits=None):
    return import_bytes(json.dumps(rows).encode(), "input.json", limits or Limits())

def test_unknown_fields_not_in_prompt_but_audited():
    record = raw(); record["custom"] = {"anything": "private"}
    event = load([record]).events[0]
    assert event.raw["custom"]["anything"] == "private"
    assert "custom.anything" not in event.fields
    assert not any("mitre" in key for key in event.fields)

def test_original_and_provenance_stable():
    content = json.dumps(raw()).encode()
    one = import_bytes(content, "one.json", Limits()).events[0]
    two = import_bytes(content, "two.json", Limits()).events[0]
    assert one.event_id == two.event_id
    assert one.file_sha256 == two.file_sha256
    assert one.file_name != two.file_name
    assert one.raw == raw()
    assert one.original_time.endswith("+03:00")
    assert one.utc_time.endswith("+00:00")

def test_invalid_and_accepted_records_counted():
    content = (ROOT / "examples/invalid.jsonl").read_bytes()
    result = import_bytes(content, "invalid.jsonl", Limits())
    assert len(result.events) == 1 and len(result.issues) == 2
    assert result.total_records == 3

def test_limits_reject_not_truncate():
    record = raw(); record["full_log"] = "x" * 5000
    result = load([record])
    assert not result.events and result.issues
    limited = load([raw(), raw()], Limits(max_events=1))
    assert len(limited.events) == 1 and limited.issues[0].code == "event_limit"
    oversize = import_bytes(b"x" * (1024 * 1024 + 1), "x.json", Limits(upload_mb=1))
    assert oversize.issues[0].code == "file_size"

def test_depth_bounded():
    record = raw(); record["data"]["nested"] = {"a": {"b": {"c": {"d": 1}}}}
    assert load([record], Limits(max_depth=3)).issues

def test_missing_values_and_time_remain_unknown():
    record = raw(); record.pop("timestamp"); record["data"]["win"]["eventdata"].pop("commandLine")
    event = load([record]).events[0]
    assert event.original_time is None and event.utc_time is None
    assert "data.win.eventdata.commandLine" not in event.fields

def test_unknown_timezone_not_assumed():
    record = raw(); record["timestamp"] = "2026-01-01T10:00:00"
    event = load([record]).events[0]
    assert not event.timezone_known and event.utc_time is None and event.time_warning

def test_bad_timestamp_preserved():
    record = raw(); record["timestamp"] = "not-time"
    event = load([record]).events[0]
    assert event.original_time == "not-time" and event.utc_time is None

def test_duplicate_count_and_deduplicated_cases():
    imported = load([raw(), raw()])
    assert imported.duplicate_records == 1 and len(imported.events) == 2
    assert len(build_cases(imported.events, Limits())[0].events) == 1

def test_links_record_rule_and_window():
    a, b, c = raw(), raw(), raw()
    a["timestamp"] = "2026-01-01T00:00:00Z"
    b["timestamp"] = "2026-01-01T00:09:00Z"
    c["timestamp"] = "2026-01-01T00:18:00Z"
    cases = build_cases(load([a,b,c]).events, Limits(window_seconds=600))
    assert sorted(len(case.events) for case in cases) == [1,2]
    assert cases[0].links[0].rule.startswith("same_host_")
    assert cases[0].links[0].delta_seconds == 540

def test_ip_alone_does_not_link():
    a, b = raw(), raw()
    b["timestamp"] = "2026-01-15T10:00:02+03:00"
    a["data"]["srcip"] = b["data"]["srcip"] = "192.0.2.1"
    b["agent"]["id"] = "002"
    assert len(build_cases(load([a,b]).events, Limits())) == 2

def test_unknown_time_is_not_linked():
    a, b = raw(), raw()
    a.pop("timestamp"); b["timestamp"] = "2026-01-01T00:00:00"
    assert len(build_cases(load([a,b]).events, Limits())) == 2

def test_invalid_array_encoding_nan():
    for content in (b"[broken]", b"\xff", b'{"rule":{"id":"1"},"agent":{"id":"1"},"data":{"v":NaN}}'):
        assert import_bytes(content, "bad.json", Limits()).issues

def test_linking_rules_can_be_disabled():
    a,b=raw(),raw();b["timestamp"]="2026-01-15T10:00:02+03:00"
    assert len(build_cases(load([a,b]).events,Limits(),enabled=[]))==2

def test_rfc3339_negative_zero_means_unknown_offset():
    record=raw();record["timestamp"]="2026-01-01T10:00:00-00:00"
    event=load([record]).events[0]
    assert not event.timezone_known and event.utc_time is None

def test_equal_timestamps_do_not_imply_order():
    a,b=raw(),raw();b["full_log"]="distinct record"
    case=build_cases(load([a,b]).events,Limits())[0]
    assert len(case.events)==2
    assert any("Одинаковые" in warning for warning in case.warnings)

def test_history_case_identity_preserves_origin():
    payload=json.dumps(raw()).encode()
    one=import_bytes(payload,"first.json",Limits()).events
    two=import_bytes(payload,"second.json",Limits()).events
    assert one[0].event_id==two[0].event_id
    assert build_cases(one,Limits())[0].case_id!=build_cases(two,Limits())[0].case_id

def test_record_limit_aggregates_rejections_and_bounds_diagnostics():
    record={"rule":{"id":"1"},"agent":{"id":"001"}}
    payload=((json.dumps(record)+"\n")*5000).encode()
    result=import_bytes(payload,"many.jsonl",Limits(max_events=2))
    assert len(result.events)==2 and result.total_records==5000
    assert result.rejected_records==4998 and result.file_errors==0
    assert len(result.issues)==1 and result.issues[0].count==4998
    assert result.issues[0].code=="event_limit"
