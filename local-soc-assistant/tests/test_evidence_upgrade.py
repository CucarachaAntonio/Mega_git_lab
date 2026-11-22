"""Controls for source exactness and independent, partial verification (no LLM/network)."""
from copy import deepcopy
import json
from pathlib import Path
import pytest
from soc_assistant.schemas import Draft, Finding, Evidence, Recommendation, TimelineClaim, LinkClaim, PriorityClaim
from soc_assistant.ingest import import_bytes
from soc_assistant.correlate import build_cases
from soc_assistant.retrieval import Retriever, Snapshot, case_query
from soc_assistant.verification import verify
from soc_assistant.service import analyze
from soc_assistant.replay import load_bundle, verify_saved
from soc_assistant.evaluation import evaluate, aggregate, experiment
from soc_assistant.priority import priority_context
from soc_assistant.evidence import resolve

FIELDS = ["data.win.eventdata.image", "data.win.eventdata.commandLine", "data.win.system.eventID", "data.win.system.providerName"]
ROOT = Path(__file__).resolve().parents[1]

class FixtureRuntime:
    load_seconds = 0
    metadata = {"backend": "TEST_STUB", "real_llm": False}
    def __init__(self, draft): self.draft = draft; self.calls = 0
    def generate(self, messages, schema): self.calls += 1; return self.draft.model_dump_json()
    def close(self): pass

def make_case(records, settings, name="control.jsonl"):
    content = "\n".join(json.dumps(r) for r in records).encode()
    result = import_bytes(content, name, settings.limits)
    assert not result.issues
    return build_cases(result.events, settings.limits)

def draft_for(case, settings):
    event = case.events[0]
    refs = [Evidence(event_id=event.event_id, field=f, value=event.fields[f]) for f in FIELDS if f in event.fields]
    chunks = Retriever(settings.path("index")).search("powershell", 8)
    source = next(c.chunk_id for c in chunks if c.technique_id == "T1059.001")
    return Draft(facts=deepcopy(refs), techniques=[Finding(technique_id="T1059.001", rationale="model hypothesis", evidence=refs, source_ids=[source])]), chunks

def test_typed_check_reads_raw_even_if_cached_fields_are_forged(settings, case):
    draft, chunks = draft_for(case, settings)
    case.events[0].fields[FIELDS[0]] = "forged.exe"
    draft.facts[0].value = "forged.exe"
    result, checks, refusals = verify(draft, case, Snapshot(settings.path("snapshot")), chunks)
    assert any(r["code"] == "content_mismatch" for r in refusals)
    assert any(c.code == "prepared_record_mismatch" for c in checks)
    assert not any(f.value == "forged.exe" for f in result.facts)

def test_two_attack_checks_survive_bad_source(settings, case):
    draft, chunks = draft_for(case, settings)
    draft.techniques[0].source_ids = ["does-not-exist"]
    result, checks, refusals = verify(draft, case, Snapshot(settings.path("snapshot")), chunks)
    finding = result.techniques[0]
    assert finding.identity_check == "passed" and finding.observation_check == "passed"
    assert finding.verdict == "analyst_required" and finding.support_state == "not_verifiable"
    assert any(r["code"] == "invalid_source" for r in refusals)

def test_source_text_and_offsets_are_verified(settings, case):
    draft, chunks = draft_for(case, settings)
    cited = next(c for c in chunks if c.chunk_id == draft.techniques[0].source_ids[0])
    cited.text = "fabricated definition"
    result, _, refusals = verify(draft, case, Snapshot(settings.path("snapshot")), chunks)
    assert result.techniques[0].observation_check == "passed"
    assert any(r["code"] == "source_integrity" for r in refusals)

def test_matrix_and_semantics_are_separate(settings, case):
    draft, chunks = draft_for(case, settings)
    snapshot = Snapshot(settings.path("snapshot"))
    snapshot.techniques["T1059.001"]["x_mitre_domains"] = ["mobile-attack"]
    result, _, refusals = verify(draft, case, snapshot, chunks)
    assert result.techniques[0].identity_check == "failed"
    assert result.techniques[0].observation_check == "passed"
    assert any(r["code"] == "wrong_attack_matrix" for r in refusals)

def test_conflicting_process_is_refuted_even_with_missing_citation(settings, case):
    draft, chunks = draft_for(case, settings)
    draft.techniques[0].technique_id = "T1053.005"
    draft.techniques[0].source_ids = []
    result, _, refusals = verify(draft, case, Snapshot(settings.path("snapshot")), chunks)
    assert result.facts and result.techniques[0].support_state == "contradicted"
    assert {r["code"] for r in refusals} >= {"contradiction", "missing_source_reference"}

def test_other_case_and_existing_wrong_record_are_rejected(settings, case):
    raw = deepcopy(case.events[0].raw)
    raw["agent"]["id"] = "unrelated-host"
    raw["data"]["win"]["eventdata"]["image"] = "different.exe"
    other = make_case([raw], settings)[0]
    draft, chunks = draft_for(case, settings)
    draft.facts[0].event_id = other.events[0].event_id
    result, _, refusals = verify(draft, case, Snapshot(settings.path("snapshot")), chunks)
    assert any(r["code"] == "invalid_event" for r in refusals)
    joined = case.model_copy(deep=True)
    joined.events.extend(other.events)
    result, _, refusals = verify(draft, joined, Snapshot(settings.path("snapshot")), chunks)
    assert any(r["code"] == "content_mismatch" for r in refusals)

def test_source_record_and_pointer_cannot_be_substituted(settings, case):
    draft, chunks = draft_for(case, settings)
    draft.facts[0].record_id = "other-record"
    draft.facts[1].json_pointer = "/agent/id"
    _, _, refusals = verify(draft, case, Snapshot(settings.path("snapshot")), chunks)
    assert {r["code"] for r in refusals} >= {"source_record_mismatch", "invalid_field"}

def test_description_labels_excluded_from_all_modes(settings, case):
    from soc_assistant.generation import build_messages
    raw = deepcopy(case.events[0].raw)
    raw["rule"]["description"] = "Ready annotation T1059.001 (not independent observation)"
    raw["data"]["expected_priority"] = "HIDDEN_PRIORITY"
    raw["data"]["T1059.001"] = True
    new_case = make_case([raw], settings)[0]
    event = new_case.events[0]
    assert "rule.description" not in event.fields
    assert event.excluded_fields["rule.description"] == "explicit_attack_code_hint"
    assert event.raw["rule"]["description"].startswith("Ready")
    annotation = event.source_annotations["/rule/description"]
    assert annotation.source_id == event.source_id and annotation.record_id == event.record_id
    assert resolve(event.raw, annotation.json_pointer) == raw["rule"]["description"]
    for mode in "ABCD":
        report = analyze(new_case, mode, settings, runtime=FixtureRuntime(Draft()))
        assert all(r.field != "rule.description" for r in report.observations)
    payload = build_messages(new_case, [], 16000)[1]["content"]
    assert "Ready annotation" not in payload and '"mitre"' not in payload
    assert "HIDDEN_PRIORITY" not in payload and "data.T1059.001" not in payload

def test_pointer_escaping_and_dotted_key_collisions(settings, case):
    raw = deepcopy(case.events[0].raw)
    raw["data"]["a.b"] = "literal"
    raw["data"]["a"] = {"b": "nested", "x/y~": [True, 1, "1"]}
    event = make_case([raw], settings)[0].events[0]
    assert event.fields["/data/a.b"] == "literal" and event.fields["/data/a/b"] == "nested"
    for field, origin in event.field_origins.items():
        actual = resolve(event.raw, origin.json_pointer)
        assert type(actual) is type(event.fields[field]) and actual == event.fields[field]

def test_duplicate_membership_keeps_every_origin(settings, case):
    raw = case.events[0].raw
    grouped = make_case([raw, raw], settings)[0]
    assert len(grouped.events) == 1
    assert [o.record_number for o in grouped.memberships[grouped.events[0].event_id]] == [1, 2]

def test_conflicting_clocks_prevent_temporal_grouping(settings, case):
    left = deepcopy(case.events[0].raw)
    left["data"]["win"]["system"]["systemTime"] = "2026-01-01T10:00:00Z"
    left["data"]["win"]["eventdata"]["utcTime"] = "2026-01-02T10:00:00Z"
    right = deepcopy(left); right["id"] = "second-record"
    cases = make_case([left, right], settings)
    assert len(cases) == 2 and all(c.events[0].time_state == "conflicting" for c in cases)
    draft, chunks = draft_for(cases[0], settings)
    draft.timeline = [TimelineClaim(event_id=cases[0].events[0].event_id, utc_time=cases[0].events[0].utc_time)]
    result, _, refusals = verify(draft, cases[0], Snapshot(settings.path("snapshot")), chunks)
    assert not result.timeline and any(r["code"] == "timeline_reproducible" for r in refusals)
    assert result.facts  # uncertainty about chronology does not erase observed process fields

def test_unobserved_causal_link_is_rejected(settings, case):
    draft, chunks = draft_for(case, settings)
    draft.links = [LinkClaim(from_event=case.events[0].event_id, to_event=case.events[0].event_id, rule="imagined", kind="causal")]
    result, _, refusals = verify(draft, case, Snapshot(settings.path("snapshot")), chunks)
    assert not result.links and any(r["code"] == "link_claim" for r in refusals)

def test_suricata_single_record_and_explicit_flow_window(settings):
    left = {"event_type": "alert", "timestamp": "2026-01-01T12:00:00Z", "sensor_name": "demo-sensor", "flow_id": 42, "src_ip": "192.0.2.10", "dest_ip": "192.0.2.20", "alert": {"signature": "synthetic test"}}
    single = make_case([left], settings)[0]
    assert single.events[0].source == "suricata" and len(single.events) == 1
    right = {**left, "timestamp": "2026-01-01T12:00:10Z", "event_type": "flow"}
    joined = make_case([left, right], settings)
    assert len(joined) == 1 and joined[0].links[0].rule == "same_flow_v1"
    assert joined[0].links[0].kind == "temporal" and joined[0].links[0].delta_seconds == 10
    right["sensor_name"] = "other-sensor"
    assert len(make_case([left, right], settings)) == 2

def test_model_unavailable_preserves_observation_and_urgency(settings, case):
    report = analyze(case, "D", settings)
    assert report.status == "technical_error" and report.errors[0]["code"] == "model_unavailable"
    assert report.observations and report.priority == "medium" and report.confirmation == "not_assessed"
    assert not report.refusals

def test_missing_snapshot_keeps_raw_facts(settings, case):
    draft, _ = draft_for(case, settings)
    settings.path("snapshot").unlink()
    report = analyze(case, "D", settings, runtime=FixtureRuntime(draft))
    assert report.status == "partial" and report.facts and report.observations
    assert report.techniques[0].identity_check == "not_checked"
    assert report.techniques[0].observation_check == "passed"
    assert report.errors and report.priority == "medium"

def test_replay_has_no_model_call_and_same_draft(settings, case):
    draft, _ = draft_for(case, settings)
    runtime = FixtureRuntime(draft)
    b = analyze(case, "B", settings, runtime=runtime)
    bundle = load_bundle(Path(b.draft_ref))
    d = analyze(case, "D", settings, runtime=runtime, reuse_bundle=bundle)
    assert runtime.calls == 1 and b.draft_id == d.draft_id
    assert d.measurement["draft_reused"] and not d.attempts
    assert d.techniques[0].verdict == "supported" and d.facts[0].json_pointer
    assert d.durations["verification"] >= 0 and d.durations["full_pass"] >= d.durations["total"]
    settings.path("index").unlink()  # Replay needs the pinned documents, not a new search.
    again = verify_saved(Path(b.draft_ref), settings)
    assert again.draft_id == b.draft_id and again.techniques[0].verdict == "supported"

def test_bundle_tampering_diagnosed(settings, case):
    b = analyze(case, "C", settings)
    path = Path(b.draft_ref)
    body = json.loads(path.read_text()); body["draft"]["facts"][0]["value"] = "edited"
    path.write_text(json.dumps(body))
    with pytest.raises(ValueError, match="checksum"): load_bundle(path)

def test_priority_claim_requires_exact_policy_and_basis(settings, case):
    draft, chunks = draft_for(case, settings)
    draft.priority = PriorityClaim(category="high", evidence=draft.facts)
    result, checks, refusals = verify(draft, case, Snapshot(settings.path("snapshot")), chunks, priority_context=priority_context(settings))
    assert result.priority is None and result.facts
    assert any(r["target"] == "priority" for r in refusals)
    draft.priority = PriorityClaim(category="medium", evidence=draft.facts)
    result, checks, _ = verify(draft, case, Snapshot(settings.path("snapshot")), chunks, priority_context=priority_context(settings))
    assert result.priority.category == "medium"
    assert any(c.target == "priority" and c.status == "passed" for c in checks)

def test_recommendation_needs_clause_conditions_and_missing_field(settings, case):
    draft, chunks = draft_for(case, settings)
    runbook = next(c for c in Retriever(settings.path("index")).search("родительский процесс", 8) if c.document_kind == "runbook")
    chunks.append(runbook)
    draft.recommendations = [Recommendation(action="review_process", condition="untrusted instruction", evidence=draft.facts[:2],
        source_ids=[runbook.chunk_id], missing_fields=["data.win.eventdata.parentImage"])]
    result, checks, _ = verify(draft, case, Snapshot(settings.path("snapshot")), chunks)
    # Demo has no parentImage; a literal runbook clause plus process evidence applies.
    assert result.recommendations[0].status == "supported"
    assert "untrusted" not in result.recommendations[0].condition
    draft.recommendations[0].action = "confirm_authorization"
    result, checks, _ = verify(draft, case, Snapshot(settings.path("snapshot")), chunks)
    assert result.recommendations[0].status == "analyst_required"

def test_retrieved_offsets_reproduce_document(settings):
    snapshot = Snapshot(settings.path("snapshot"))
    bodies = {obj["id"]: obj.get("description", "") for obj, _, _ in snapshot.documents}
    bodies["local-runbook-v1"] = (settings.root / "knowledge/runbook.md").read_text()
    for chunk in Retriever(settings.path("index")).search("powershell process investigation", 8):
        assert bodies[chunk.document_id][chunk.start_char:chunk.end_char] == chunk.text

def test_evaluator_uses_raw_and_gold_not_verifier_verdict(settings, case):
    draft, _ = draft_for(case, settings)
    report = analyze(case, "B", settings, runtime=FixtureRuntime(draft))
    report.facts[0].value = "forged.exe"
    case.events[0].fields[FIELDS[0]] = "forged.exe"
    gold = {"scenario_id": "control", "techniques": ["T1059.001"], "priority": "medium", "should_abstain": False, "required_evidence_fields": FIELDS}
    row = evaluate(report, case, gold)
    assert row["fact_valid"] == 3 and row["tp"] == 1
    summary = aggregate([row])["B"]
    assert summary["metrics"]["fact_reference_accuracy"] == {"numerator": 3, "denominator": 4, "value": .75, "applicable": True}

def test_empty_denominator_is_na_and_claim_opportunities_count(settings, case):
    report = analyze(case, "B", settings, runtime=FixtureRuntime(Draft()))
    gold = {"scenario_id": "control", "techniques": ["T1059.001"], "priority": "medium", "should_abstain": False, "required_evidence_fields": FIELDS,
            "opportunities": [{"technique_id": "T1059.001", "expected": "conclude"}, {"technique_id": "T1053.005", "expected": "abstain"}]}
    row = evaluate(report, case, gold); summary = aggregate([row])["B"]
    assert summary["metrics"]["precision"]["value"] is None
    assert summary["metrics"]["technique_opportunity_coverage"]["denominator"] == 2
    assert row["fn"] == 1

def test_experiment_pairs_b_d_without_second_generation(settings, monkeypatch, tmp_path):
    import shutil
    shutil.copytree(ROOT / "examples", settings.root / "examples")
    shutil.copytree(ROOT / "evaluation", settings.root / "evaluation")
    content = (settings.root / "examples/scenarios/ps_admin_1.jsonl").read_bytes()
    case = build_cases(import_bytes(content, "examples/scenarios/ps_admin_1.jsonl", settings.limits).events, settings.limits)[0]
    draft, _ = draft_for(case, settings)
    runtime = FixtureRuntime(draft)
    monkeypatch.setattr("soc_assistant.generation.LlamaRuntime", lambda config: runtime)
    output = tmp_path / "paired"
    summary = experiment(settings, ["B", "D"], 3, "tune", output, scenario_ids=["ps_admin_1"])
    rows = json.loads((output / "individual.json").read_text())
    assert runtime.calls == 3 and len(rows) == 6
    for repeat in (1, 2, 3):
        b, d = [r for r in rows if r["repeat"] == repeat]
        assert b["mode"] == "B" and d["mode"] == "D" and b["draft_id"] == d["draft_id"]
        assert d["draft_reused"] and d["verification_seconds"] is not None

def test_prior_report_format_still_loads():
    from soc_assistant.schemas import Report
    path = next((ROOT / "validation/comparison").glob("run-*.json"))
    old = Report.model_validate_json(path.read_text())
    assert old.run_id and old.observations == [] and old.draft_id is None

def test_manager_identity_prevents_cross_source_host_join(settings, case):
    left = deepcopy(case.events[0].raw); left["manager"] = {"name": "manager-a"}
    right = deepcopy(left); right["manager"] = {"name": "manager-b"}; right["id"] = "different"
    cases = make_case([left, right], settings)
    assert len(cases) == 2 and cases[0].events[0].source_id != cases[1].events[0].source_id

def test_link_checks_enforce_whole_case_window(settings, case):
    records = []
    for index, minute in enumerate((0, 9, 18)):
        raw = deepcopy(case.events[0].raw)
        raw["id"] = str(index); raw["timestamp"] = f"2026-01-01T10:{minute:02d}:00Z"
        records.append(raw)
    groups = make_case(records, settings)
    assert len(groups) == 2
    prepared = groups[0].model_copy(deep=True)
    prepared.events.extend(groups[1].events)
    from soc_assistant.schemas import Link
    left, right = prepared.events[1:]
    from soc_assistant.correlate import _relation
    rule, reasons = _relation(left, right, settings.correlation.enabled)
    prepared.links.append(Link(from_event=left.event_id, to_event=right.event_id, rule=rule, reasons=reasons, delta_seconds=540))
    draft, chunks = draft_for(prepared, settings)
    _, checks, _ = verify(draft, prepared, Snapshot(settings.path("snapshot")), chunks)
    assert any(c.target.startswith("prepared_link:") and c.status == "failed" for c in checks)

def test_control_gold_hashes_and_related_split_are_fixed():
    import hashlib
    gold = json.loads((ROOT / "evaluation/controls.json").read_text())
    families = {}
    for scenario in gold["scenarios"]:
        assert hashlib.sha256((ROOT / scenario["input"]).read_bytes()).hexdigest() == scenario["sha256"]
        families.setdefault(scenario["family"], set()).add(scenario["split"])
        assert scenario["assertions"] and scenario["opportunities"]
    assert all(len(splits) == 1 for splits in families.values())

def test_cli_invalid_saved_draft_is_diagnostic(settings, tmp_path, capsys):
    from soc_assistant.cli import main
    path = tmp_path / "invalid.bundle.json"; path.write_text('{"draft": "wrong"}')
    result = main(["--config", str(settings.root / "config.toml"), "verify", "--bundle", str(path), "--out", str(tmp_path / "out")])
    assert result == 2
    response = json.loads(capsys.readouterr().out)
    assert response["code"] == "invalid_draft_format" and response["model_called"] is False

def test_boolean_identifiers_are_not_numeric_identifiers(settings, case):
    raw = deepcopy(case.events[0].raw)
    raw["data"]["win"]["system"]["eventID"] = True
    altered = make_case([raw], settings)[0]
    report = analyze(altered, "C", settings)
    assert not report.techniques and report.priority == "unknown"
    raw["agent"]["id"] = True
    assert import_bytes(json.dumps(raw).encode(), "invalid.json", settings.limits).issues
    a = {"event_type": "flow", "timestamp": "2026-01-01T12:00:00Z", "sensor_name": "typed-flow", "flow_id": True}
    b = {**a, "timestamp": "2026-01-01T12:00:01Z", "flow_id": 1}
    assert len(make_case([a, b], settings)) == 2
