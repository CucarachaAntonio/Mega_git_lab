"""Explicit online preparation only. Never imported by the analysis pipeline."""
from __future__ import annotations
import hashlib
import json
import urllib.request
from pathlib import Path
from .config import Settings
from .retrieval import build_index, file_hash

MODEL_REPO = "Qwen/Qwen2.5-1.5B-Instruct-GGUF"
MODEL_REVISION = "91cad51170dc346986eccefdc2dd33a9da36ead9"
MODEL_FILE = "qwen2.5-1.5b-instruct-q4_k_m.gguf"
ATTACK_RELEASE = "v18.0"
ATTACK_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v18.0/enterprise-attack/enterprise-attack.json"

def download(url: str, target: Path, expected_sha: str | None = None):
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".part")
    digest = hashlib.sha256()
    try:
        with urllib.request.urlopen(url, timeout=90) as response, temporary.open("wb") as output:
            while block := response.read(1024 * 1024):
                output.write(block); digest.update(block)
        if expected_sha and digest.hexdigest() != expected_sha:
            raise ValueError("Контрольная сумма загрузки не совпала")
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)
    return digest.hexdigest()

def prepare_model(settings: Settings):
    if settings.model_path.name != MODEL_FILE:
        raise ValueError("Автоподготовка поддерживает только исходную модель; другую GGUF установите вручную")
    url = f"https://huggingface.co/{MODEL_REPO}/resolve/{MODEL_REVISION}/{MODEL_FILE}"
    # The pinned revision provides the expected LFS hash; TLS is never disabled.
    api = f"https://huggingface.co/api/models/{MODEL_REPO}/revision/{MODEL_REVISION}?blobs=true"
    with urllib.request.urlopen(api, timeout=60) as response:
        metadata = json.load(response)
    entry = next(item for item in metadata["siblings"] if item["rfilename"] == MODEL_FILE)
    expected = entry["lfs"]["sha256"]
    if not settings.model_path.exists() or file_hash(settings.model_path) != expected:
        download(url, settings.model_path, expected)
    manifest = {"repository": MODEL_REPO, "revision": MODEL_REVISION, "file": MODEL_FILE,
                "sha256": expected, "license": "Apache-2.0", "bytes": settings.model_path.stat().st_size}
    settings.model_path.with_suffix(".manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest

def prepare_attack(settings: Settings):
    # Does not silently replace the configured demo snapshot.
    target = settings.root / "knowledge/enterprise-full.json"
    bundled_manifest = settings.root / "knowledge/manifest.json"
    metadata = json.loads(bundled_manifest.read_text(encoding="utf-8"))
    expected = metadata["attack_original_sha256"]
    if not target.exists() or file_hash(target) != expected:
        download(ATTACK_URL, target, expected)
    return {"path": str(target), "release": ATTACK_RELEASE, "sha256": expected,
            "next": "Укажите paths.snapshot=knowledge/enterprise-full.json в config.toml и перестройте индекс"}

def prepare_index(settings: Settings):
    return build_index(settings.path("snapshot"), settings.path("index"), settings.limits.rag_chunk_chars,
                       settings.root / "knowledge/runbook.md")
