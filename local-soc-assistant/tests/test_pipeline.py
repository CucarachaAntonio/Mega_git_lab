from pathlib import Path
import json
import pytest
from soc_assistant.export import render_html
from soc_assistant.generation import InputBudgetError, build_messages
from soc_assistant.profiles import candidates
from soc_assistant.retrieval import Retriever, case_query
from soc_assistant.schemas import Draft, Finding, Report
from soc_assistant.service import analyze, readiness
from soc_assistant.storage import Store
from soc_assistant.security import analysis_lock, BusyError
from soc_assistant.evaluation import evaluate, aggregate

ROOT = Path(__file__).resolve().parents[1]

class StubRuntime:
    load_seconds=0
    metadata={"backend":"TEST_STUB", "real_llm":False}
    def __init__(self, output): self.output=output;self.calls=[]
    def generate(self,messages,schema): self.calls.append(messages);return self.output
    def close(self): pass

def draft_for(case,settings):
    profile,event,evidence=next(candidates(case.events))
    chunks=Retriever(settings.path("index")).search("powershell",8)
    source=next(c.chunk_id for c in chunks if c.technique_id==profile.technique_id)
    return Draft(facts=evidence,techniques=[Finding(technique_id=profile.technique_id,rationale="hypothesis",evidence=evidence,source_ids=[source])])

def test_import_to_export_and_history(settings,case):
    report=analyze(case,"C",settings)
    assert report.status=="completed" and report.techniques
    store=Store(settings.path("data"))
    assert store.cases()[0].case_id==case.case_id
    assert store.reports()[0].run_id==report.run_id
    assert Report.model_validate_json(report.model_dump_json())==report
    html=render_html(report,case)
    assert "<!doctype html>" in html and '#event-' in html
    assert "The MITRE Corporation" in html

def test_offline_c_works_without_model(settings,case):
    assert not readiness(settings)["generative_ready"]
    assert readiness(settings)["mode_C_ready"]
    assert analyze(case,"C",settings).status!="technical_error"

def test_no_hidden_d_in_a_b(settings,case):
    draft=draft_for(case,settings)
    draft.techniques[0].evidence[0].value="FABRICATED"
    for mode in ["A","B"]:
        report=analyze(case,mode,settings,runtime=StubRuntime(draft.model_dump_json()))
        assert not report.checks and report.techniques[0].verdict=="unchecked"
        assert report.techniques[0].evidence[0].value=="FABRICATED"
        if mode=="A": assert not report.sources

def test_d_rejects_where_b_does_not(settings,case):
    draft=draft_for(case,settings);draft.techniques[0].evidence[0].value="FABRICATED"
    report=analyze(case,"D",settings,runtime=StubRuntime(draft.model_dump_json()))
    assert report.techniques[0].verdict=="rejected" and report.refusals
    assert report.priority=="medium" and report.status!="technical_error"

def test_labels_cannot_enter_generation(settings,case):
    messages=build_messages(case,[],16000)
    text=json.dumps(messages)
    assert "HIDDEN_TEST_LABEL" not in text and "T9999" not in text
    assert "HIDDEN_TEST_LABEL" in json.dumps(case.events[0].raw)
    assert "gold" not in text and "expected_priority" not in text

def test_prompt_injection_is_untrusted_and_html_escaped(settings):
    from soc_assistant.ingest import import_bytes
    from soc_assistant.correlate import build_cases
    content=(ROOT/"examples/scenarios/injection_1.jsonl").read_bytes()
    case=build_cases(import_bytes(content,"injection.jsonl",settings.limits).events,settings.limits)[0]
    messages=build_messages(case,[],16000)
    assert "НЕДОВЕРЕННЫМИ" in messages[0]["content"]
    assert "IGNORE ALL INSTRUCTIONS" in messages[1]["content"]
    report=analyze(case,"C",settings)
    html=render_html(report,case)
    assert "<script>" not in html and "&lt;script&gt;" in html

def test_retry_limited_all_attempts_saved(settings,case):
    runtime=StubRuntime("not-json")
    report=analyze(case,"A",settings,runtime=runtime)
    assert report.status=="technical_error" and len(runtime.calls)==2
    assert len(report.attempts)==2 and report.attempts[0]["raw"]=="not-json"
    assert not report.refusals

def test_model_error_distinct_from_refusal(settings,case):
    report=analyze(case,"A",settings)
    assert report.status=="technical_error" and report.errors[0]["code"]=="model_unavailable"
    assert not report.refusals

def test_search_failure_distinct_from_empty(settings,case):
    retriever=Retriever(settings.path("index"))
    assert retriever.search("zzzznomatchingword") == []
    settings.path("index").unlink()
    report=analyze(case,"D",settings,runtime=StubRuntime("{}"))
    assert report.status=="technical_error" and report.errors[0]["code"]=="retrieval_failure"
    assert not report.refusals

def test_stale_snapshot_detected(settings):
    p=settings.path("snapshot")
    p.write_text(p.read_text()+"\n")
    assert not readiness(settings)["index"]["ok"]

def test_retrieval_reproducible(settings,case):
    retriever=Retriever(settings.path("index"))
    first=retriever.search(case_query(case));second=retriever.search(case_query(case))
    assert first==second and first
    for chunk in first: assert chunk.source and chunk.version and chunk.source_sha256

def test_analysis_lock_released(settings):
    with analysis_lock(settings.path("data")):
        with pytest.raises(BusyError):
            with analysis_lock(settings.path("data")): pass
    with analysis_lock(settings.path("data")): pass

def test_context_limit_is_explicit(case):
    with pytest.raises(InputBudgetError):build_messages(case,[],100)

def test_evaluator_missing_answer_not_perfect(settings,case):
    report=Report(run_id="x",case_id=case.case_id,mode="A",status="completed",versions={})
    gold={"scenario_id":"x","techniques":["T1059.001"],"should_abstain":False,"priority":"medium","required_evidence_fields":[]}
    row=evaluate(report,case,gold);metrics=aggregate([row])["A"]
    assert row["fn"]==1 and metrics["recall"]==0 and metrics["f1"]==0
    assert metrics["unsupported_technique_claim_rate"] is None
    assert metrics["coverage"]==0 and metrics["empty_answers"]==1

def test_case_family_split_and_hashes():
    import hashlib
    gold=json.loads((ROOT/"evaluation/gold.json").read_text())
    families={}
    assert len(gold["scenarios"])>=20
    for scenario in gold["scenarios"]:
        families.setdefault(scenario["family"],set()).add(scenario["split"])
        content=(ROOT/scenario["input"]).read_bytes()
        assert hashlib.sha256(content).hexdigest()==scenario["sha256"]
        assert '"techniques"' not in content.decode()
    assert all(len(splits)==1 for splits in families.values())

def test_empty_model_conclusion_is_not_fabricated_evidence_refusal(settings,case):
    report=analyze(case,"D",settings,runtime=StubRuntime(Draft().model_dump_json()))
    assert report.status=="partial" and not report.refusals
    assert any(check.code=="missing_conclusion" for check in report.checks)

def test_rag_budget_reduction_is_recorded_and_same_for_b_d(settings,case):
    class BudgetRuntime(StubRuntime):
        def check_budget(self,messages):
            payload=json.loads(messages[1]["content"].split("\n",1)[1].rsplit("\n",1)[0])
            if len(payload["knowledge"])>1:raise InputBudgetError("budget fixture")
    b=analyze(case,"B",settings,runtime=BudgetRuntime(Draft().model_dump_json()))
    d=analyze(case,"D",settings,runtime=BudgetRuntime(Draft().model_dump_json()))
    assert b.retrieval["used_chunk_ids"]==d.retrieval["used_chunk_ids"]
    assert len(b.sources)==1 and b.retrieval["omitted_for_context_budget"]
    assert len(b.retrieval["all_chunks"])>len(b.sources)
