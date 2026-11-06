from __future__ import annotations
import hashlib
import json
import tomllib
from pathlib import Path
from pydantic import BaseModel, ConfigDict, Field
from typing import Literal

class Limits(BaseModel):
    model_config = ConfigDict(extra="forbid")
    upload_mb: int = Field(10, ge=1, le=100)
    max_events: int = Field(2000, ge=1, le=10000)
    max_field_chars: int = Field(4096, ge=128, le=16384)
    max_depth: int = Field(16, ge=2, le=32)
    max_case_events: int = Field(16, ge=1, le=64)
    window_seconds: int = Field(600, ge=1, le=86400)
    rag_top_k: int = Field(4, ge=1, le=8)
    rag_chunk_chars: int = Field(1800, ge=256, le=4000)

class ModelConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = "models/qwen2.5-1.5b-instruct-q4_k_m.gguf"
    context: int = Field(4096, ge=1024, le=8192)
    max_tokens: int = Field(1100, ge=64, le=2048)
    threads: int = Field(4, ge=1, le=16)
    batch: int = Field(128, ge=16, le=256)
    temperature: float = Field(0.1, ge=0, le=1)
    seed: int = 42
    format_retries: int = Field(1, ge=0, le=1)
    max_seconds: int = Field(600, ge=30, le=1800)
    max_input_chars: int = Field(16000, ge=1000, le=24000)

class Correlation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: list[Literal["same_host_process_v1", "same_host_account_v1"]] = ["same_host_process_v1", "same_host_account_v1"]

class Settings(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    root: Path
    paths: dict[str, str]
    limits: Limits = Limits()
    model: ModelConfig = ModelConfig()
    priority: dict = {}
    correlation: Correlation = Correlation()

    def path(self, key: str) -> Path:
        return (self.root / self.paths[key]).resolve()

    @property
    def model_path(self) -> Path:
        return (self.root / self.model.path).resolve()

    @property
    def fingerprint(self) -> str:
        data = self.model_dump(mode="json", exclude={"root"})
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

def load_settings(path: str | Path = "config.toml") -> Settings:
    path = Path(path).resolve()
    return Settings(root=path.parent, **tomllib.loads(path.read_text(encoding="utf-8")))
