from pathlib import Path
import shutil
import pytest
from soc_assistant.config import load_settings
from soc_assistant.ingest import import_bytes
from soc_assistant.correlate import build_cases
from soc_assistant.prepare import prepare_index

ROOT = Path(__file__).resolve().parents[1]

@pytest.fixture
def settings(tmp_path):
    # Fast tests must never inherit production paths or require the full snapshot/model.
    (tmp_path / "config.toml").write_text('''[paths]
data = "data"
snapshot = "knowledge/enterprise-demo.json"
index = "data/knowledge.sqlite"
assets = "knowledge/assets.json"
[model]
path = "models/absent-test-fixture.gguf"
''', encoding="utf-8")
    shutil.copytree(ROOT / "knowledge", tmp_path / "knowledge", ignore=shutil.ignore_patterns("enterprise-full.json"))
    (tmp_path / "knowledge/assets.json").write_text("{}", encoding="utf-8")
    license_dir = tmp_path / "docs/licenses"
    license_dir.mkdir(parents=True)
    shutil.copy(ROOT / "docs/licenses/MITRE-ATTACK.txt", license_dir / "MITRE-ATTACK.txt")
    config = load_settings(tmp_path / "config.toml")
    prepare_index(config)
    return config

@pytest.fixture
def case(settings):
    imported = import_bytes((ROOT / "examples/demo.jsonl").read_bytes(), "demo.jsonl", settings.limits)
    assert not imported.issues
    return build_cases(imported.events, settings.limits)[0]
