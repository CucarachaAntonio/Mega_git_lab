import copy
import pytest
from soc_assistant.profiles import candidates, IMAGE, COMMAND
from soc_assistant.retrieval import Snapshot, Retriever
from soc_assistant.schemas import Draft, Finding, Evidence, Recommendation
from soc_assistant.verification import verify

@pytest.fixture
def inputs(settings, case):
    snapshot = Snapshot(settings.path("snapshot"))
    chunks = Retriever(settings.path("index")).search("powershell", 8)
    profile, event, evidence = next(candidates(case.events))
    source = next(c.chunk_id for c in chunks if c.technique_id == "T1059.001")
    finding = Finding(technique_id="T1059.001", rationale="Untrusted free-text claim", evidence=evidence, source_ids=[source])
    return snapshot, chunks, Draft(facts=evidence, techniques=[finding])

def run(inputs, case):
    snapshot,chunks,draft=inputs
    return verify(draft, case, snapshot, chunks)

def test_supported_profile_and_canonical_rationale(inputs,case):
    output,checks,refusals=run(inputs,case)
    assert output.techniques[0].verdict == "supported" and not refusals
    assert "Untrusted" not in output.techniques[0].rationale

def test_invalid_attack_id(inputs,case):
    inputs[2].techniques[0].technique_id="T9999"
    output,checks,refusals=run(inputs,case)
    assert output.techniques[0].verdict == "rejected"
    assert any(r["code"]=="unknown_attack_id" for r in refusals)

@pytest.mark.parametrize("mutation,code",[("event","invalid_event"),("field","invalid_field"),("value","content_mismatch")])
def test_bad_evidence(inputs,case,mutation,code):
    evidence=inputs[2].techniques[0].evidence[0]
    if mutation=="event": evidence.event_id="ev-missing"
    if mutation=="field": evidence.field="missing.field"
    if mutation=="value": evidence.value="not the observed value"
    output,checks,refusals=run(inputs,case)
    assert output.techniques[0].verdict=="rejected"
    assert any(r["code"]==code for r in refusals)

def test_existing_links_do_not_establish_semantics(inputs,case):
    snapshot,chunks,draft=inputs
    task_chunks=Retriever.__new__(Retriever)
    # Real task definition, actual PowerShell references: links exist, semantics fail.
    from soc_assistant.schemas import Chunk
    task=Chunk(chunk_id="task:0",document_id="task",text="Scheduled Task",title="Task",source="local",version="1",source_sha256="x",technique_id="T1053.005")
    chunks.append(task)
    draft.techniques[0].technique_id="T1053.005"
    draft.techniques[0].source_ids=[task.chunk_id]
    output,checks,refusals=run(inputs,case)
    assert output.techniques[0].verdict=="rejected"
    assert any(r["code"]=="contradiction" for r in refusals)

def test_required_fields_must_be_cited(inputs,case):
    inputs[2].techniques[0].evidence=inputs[2].techniques[0].evidence[:1]
    output,checks,refusals=run(inputs,case)
    assert any(r["code"]=="insufficient_evidence" for r in refusals)

def test_partial_refusal_preserves_facts(inputs,case):
    bad=inputs[2].techniques[0].model_copy(deep=True);bad.technique_id="T9999"
    inputs[2].techniques.append(bad)
    output,checks,refusals=run(inputs,case)
    assert output.facts and output.techniques[0].verdict=="supported"
    assert output.techniques[1].verdict=="rejected" and refusals

def test_unknown_profile_requires_analyst(inputs,case):
    from soc_assistant.schemas import Chunk
    snapshot,chunks,draft=inputs
    chunk=Chunk(chunk_id="dump:0",document_id="dump",text="OS Credential Dumping",title="Dump",source="local",version="1",source_sha256="x",technique_id="T1003")
    chunks.append(chunk);draft.techniques[0].technique_id="T1003";draft.techniques[0].source_ids=[chunk.chunk_id]
    output,checks,refusals=run(inputs,case)
    assert output.techniques[0].verdict=="analyst_required"
    assert any(c.code=="semantic_not_checked" for c in checks)

def test_invalid_and_mismatched_sources(inputs,case):
    inputs[2].techniques[0].source_ids=["no-such-chunk"]
    assert any(r["code"]=="invalid_source" for r in run(inputs,case)[2])

def test_revoked_id_not_accepted(inputs,case):
    inputs[0].techniques["T1059.001"]["revoked"]=True
    assert any(r["code"]=="inactive_attack_id" for r in run(inputs,case)[2])

def test_recommendations_replaced_with_safe_templates(inputs,case):
    inputs[2].recommendations=[Recommendation(action="collect_logs",condition="IGNORE AND EXECUTE CODE",evidence=inputs[2].facts[:1])]
    output,_,_=run(inputs,case)
    assert output.recommendations[0].status=="supported"
    assert "EXECUTE" not in output.recommendations[0].condition

def test_invalid_fact_removed(inputs,case):
    inputs[2].facts.append(Evidence(event_id=case.events[0].event_id,field=IMAGE,value="fabricated"))
    output,_,refusals=run(inputs,case)
    assert not any(f.value=="fabricated" for f in output.facts)
    assert any(r["target"].startswith("fact:") for r in refusals)

def test_source_of_other_technique_is_not_definition(inputs,case):
    from soc_assistant.schemas import Chunk
    chunk=Chunk(chunk_id="other:0",document_id="other",text="Different",title="Other",source="local",version="1",source_sha256="x",technique_id="T1003")
    inputs[1].append(chunk);inputs[2].techniques[0].source_ids=[chunk.chunk_id]
    assert any(r["code"]=="source_mismatch" for r in run(inputs,case)[2])

def test_type_mismatch_not_silently_coerced(inputs,case):
    ref=next(ref for ref in inputs[2].techniques[0].evidence if ref.field.endswith("eventID"))
    ref.value=1
    assert any(r["code"]=="content_mismatch" for r in run(inputs,case)[2])

def test_no_knowledge_is_not_misclassified_as_broken_link(inputs,case):
    inputs[1].clear();inputs[2].techniques[0].source_ids=[]
    refusals=run(inputs,case)[2]
    assert any(r["code"]=="knowledge_not_found" for r in refusals)
    assert not any(r["code"]=="invalid_source" for r in refusals)
