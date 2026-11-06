import os
import subprocess
import sys
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parents[1]

def test_external_network_blocked_localhost_allowed():
    code='''
import socket
from soc_assistant.security import offline_guard
offline_guard()
for action in (lambda:socket.getaddrinfo("example.com",443),lambda:socket.socket().connect(("203.0.113.1",443))):
 try:action()
 except PermissionError:pass
 else:raise AssertionError("external request allowed")
s=socket.socket();s.bind(("127.0.0.1",0));s.close()
'''
    result=subprocess.run([sys.executable,"-c",code],cwd=ROOT,capture_output=True,text=True)
    assert result.returncode==0,result.stderr

def test_streamlit_import_demo_and_analyze(settings,monkeypatch):
    from streamlit.testing.v1 import AppTest
    import shutil
    shutil.copytree(ROOT/"examples",settings.root/"examples")
    monkeypatch.setenv("SOC_CONFIG",str(settings.root/"config.toml"))
    app=AppTest.from_file(str(ROOT/"app.py"),default_timeout=30).run()
    assert not app.exception
    next(b for b in app.button if b.label=="Загрузить демонстрационный случай").click().run()
    assert not app.exception
    next(b for b in app.button if b.label=="Запустить локальный анализ").click().run()
    assert not app.exception
    assert any(m.value=="средний" for m in app.metric)
    assert settings.path("data").joinpath("history.sqlite").exists()

@pytest.mark.integration
def test_real_llm_local_pipeline():
    if os.environ.get("SOC_REAL_LLM")!="1":pytest.skip("Set SOC_REAL_LLM=1; requires prepared real model")
    from soc_assistant.config import load_settings
    from soc_assistant.service import analyze
    from soc_assistant.ingest import import_bytes
    from soc_assistant.correlate import build_cases
    settings=load_settings(os.environ.get("SOC_REAL_CONFIG",str(ROOT/"config.toml")))
    case=build_cases(import_bytes((ROOT/"examples/demo.jsonl").read_bytes(),"demo.jsonl",settings.limits).events,settings.limits)[0]
    report=analyze(case,"D",settings)
    assert report.versions.get("runtime",{}).get("backend")=="llama-cpp-python"
    assert report.status!="technical_error",report.errors
    assert report.attempts and report.attempts[0]["raw"]

@pytest.mark.integration
def test_real_runtime_schema_compatibility():
    if os.environ.get("SOC_REAL_LLM")!="1":pytest.skip("Set SOC_REAL_LLM=1 for real runtime compatibility")
    import json
    from llama_cpp import LlamaGrammar
    from soc_assistant.schemas import Draft
    grammar=LlamaGrammar.from_json_schema(json.dumps(Draft.model_json_schema()),verbose=False)
    assert grammar._grammar

@pytest.mark.integration
def test_real_llm_injection_containment():
    if os.environ.get("SOC_REAL_LLM")!="1":pytest.skip("Set SOC_REAL_LLM=1 for a real adversarial input")
    from soc_assistant.config import load_settings
    from soc_assistant.service import analyze
    from soc_assistant.ingest import import_bytes
    from soc_assistant.correlate import build_cases
    settings=load_settings(os.environ.get("SOC_REAL_CONFIG",str(ROOT/"config.toml")))
    content=(ROOT/"examples/scenarios/injection_1.jsonl").read_bytes()
    case=build_cases(import_bytes(content,"injection_1.jsonl",settings.limits).events,settings.limits)[0]
    report=analyze(case,"D",settings)
    assert report.status!="technical_error",report.errors
    assert report.versions["runtime"].get("real_llm") is True
    assert report.priority=="low"
    assert not any(f.technique_id=="T1003" and f.verdict=="supported" for f in report.techniques)
    assert report.attempts and "IGNORE ALL INSTRUCTIONS" in report.attempts[0]["messages"][1]["content"]
