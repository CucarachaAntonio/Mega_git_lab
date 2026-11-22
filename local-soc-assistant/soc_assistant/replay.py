"""Portable draft bundle, with one copy of raw telemetry for paired B/D runs."""
from __future__ import annotations
from pathlib import Path
import json
from pydantic import ValidationError
from .schemas import DraftBundle
from .evidence import digest

BUNDLE_VERSION = "draft-bundle-1.0"

class BundleFormatError(ValueError): pass
class BundleIntegrityError(ValueError): pass

def bundle_identity(bundle: DraftBundle):
    return "draft-" + digest(bundle.model_dump(exclude={"bundle_id", "durations", "attempts", "origin_run_id"}))

def save_bundle(bundle: DraftBundle, directory: Path):
    bundle.bundle_id = bundle_identity(bundle)
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / (bundle.bundle_id + ".json")
    if not target.exists(): target.write_text(bundle.model_dump_json(indent=2), encoding="utf-8")
    return target

def load_bundle(path: Path, max_mb=64):
    if path.stat().st_size > max_mb * 1024 * 1024: raise BundleFormatError("Draft bundle exceeds limit")
    try:
        bundle = DraftBundle.model_validate_json(path.read_text(encoding="utf-8"))
    except (ValidationError, UnicodeError, json.JSONDecodeError) as exc:
        raise BundleFormatError("Saved draft does not conform to DraftBundle schema") from exc
    if bundle.bundle_id != bundle_identity(bundle): raise BundleIntegrityError("Draft bundle checksum mismatch")
    return bundle

def verify_saved(path: Path, settings, persist=True):
    return verify_bundle(load_bundle(path), settings, persist=persist)

def verify_bundle(bundle, settings, persist=True):
    from .service import analyze
    return analyze(bundle.case, "D", settings, persist=persist, reuse_bundle=bundle)

class SavedDraftRuntime:
    """Deterministic mechanical experiment. Never represents an LLM measurement."""
    load_seconds = 0.0
    model = None
    metadata = {"backend": "SAVED_DRAFT_TEST_FIXTURE", "real_llm": False,
                "warning": "Only pipeline mechanics; no generation-quality or RAG-effect estimate"}
    def __init__(self, directory): self.directory = Path(directory); self.selected = None; self.calls = 0
    def select(self, scenario, mode):
        self.selected = self.directory / (scenario + "." + ("A" if mode == "A" else "B") + ".json")
    def generate(self, messages, schema):
        if self.selected is None or not self.selected.is_file():
            from .generation import ModelUnavailable
            raise ModelUnavailable("Сохранённый тестовый черновик отсутствует")
        self.calls += 1
        self.metadata = {**self.metadata, "fixture": self.selected.name, "fixture_sha256": digest(self.selected.read_text(encoding="utf-8")), "calls": self.calls}
        return self.selected.read_text(encoding="utf-8")
    def close(self): pass
