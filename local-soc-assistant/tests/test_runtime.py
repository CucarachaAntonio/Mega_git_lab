import pytest
from soc_assistant.generation import LlamaRuntime, ModelTimeoutError
from soc_assistant.schemas import Draft
from soc_assistant.service import analyze

class FakeModel:
    """Token stream fixture only; this is not a local model integration test."""
    def __init__(self): self.closed=False
    def tokenize(self,text,add_bos=False):return [1]
    def reset(self): pass
    def create_chat_completion(self,**kwargs):
        try:
            yield {"choices":[{"delta":{"content":"{"},"finish_reason":None}]}
            yield {"choices":[{"delta":{"content":"}"},"finish_reason":"stop"}]}
        finally:self.closed=True

def test_stream_assembly_closes_generator(settings):
    runtime=LlamaRuntime(settings);runtime.model=FakeModel();runtime.metadata["real_llm"]=False;runtime._grammar_for=lambda schema: None
    result=runtime.generate([{"role":"user","content":"data"}],Draft.model_json_schema())
    assert result=="{}" and runtime.model.closed
    assert runtime.metadata["last_generation"]["finish_reason"]=="stop"

def test_timeout_keeps_partial_and_closes_stream(settings,monkeypatch):
    runtime=LlamaRuntime(settings);runtime.model=FakeModel();runtime.metadata["real_llm"]=False;runtime._grammar_for=lambda schema: None
    from types import SimpleNamespace
    times=iter([0,1000]);monkeypatch.setattr("soc_assistant.generation.time",SimpleNamespace(perf_counter=lambda:next(times)))
    with pytest.raises(ModelTimeoutError):runtime.generate([],Draft.model_json_schema())
    assert runtime.last_partial=="{" and runtime.model.closed

def test_timeout_is_technical_and_partial_response_saved(settings,case):
    class TimeoutRuntime:
        model=None
        load_seconds=0
        metadata={"backend":"TEST_TIMEOUT_STUB","real_llm":False}
        last_partial='{"facts":['
        def generate(self,*args):raise ModelTimeoutError("Timeout fixture")
    report=analyze(case,"D",settings,runtime=TimeoutRuntime())
    assert report.status=="technical_error" and report.errors[0]["code"]=="model_timeout"
    assert report.attempts[0]["raw"]=='{"facts":[' and not report.refusals

def test_cancelled_generation_not_reported_completed(settings,case):
    class InterruptedRuntime:
        model=None
        load_seconds=0
        metadata={"backend":"TEST_INTERRUPT_STUB","real_llm":False}
        last_partial="partial response fixture"
        def generate(self,*args):raise KeyboardInterrupt()
    report=analyze(case,"D",settings,runtime=InterruptedRuntime())
    assert report.status=="technical_error" and report.errors[0]["code"]=="cancelled"
    assert report.attempts[0]["raw"]=="partial response fixture"

def test_unsupported_grammar_never_silently_falls_back(settings,monkeypatch):
    import sys
    from types import SimpleNamespace
    from soc_assistant.generation import GrammarCompileError
    class BrokenGrammar:
        @staticmethod
        def from_json_schema(*args,**kwargs):raise AssertionError("unsupported fixture")
    monkeypatch.setitem(sys.modules,"llama_cpp",SimpleNamespace(LlamaGrammar=BrokenGrammar))
    runtime=LlamaRuntime(settings)
    with pytest.raises(GrammarCompileError):runtime._grammar_for(Draft.model_json_schema())
    assert not runtime.grammar_cache

def test_framework_stop_preserves_technical_status(settings,case):
    from soc_assistant.storage import Store
    class StopRuntime:
        model=None
        load_seconds=0
        metadata={"backend":"TEST_STOP_STUB","real_llm":False}
        last_partial="unfinished fixture"
        def generate(self,*args):raise SystemExit("framework stop fixture")
    with pytest.raises(SystemExit):analyze(case,"D",settings,runtime=StopRuntime())
    report=Store(settings.path("data")).reports()[0]
    assert report.status=="technical_error" and report.errors[0]["code"]=="interrupted"
