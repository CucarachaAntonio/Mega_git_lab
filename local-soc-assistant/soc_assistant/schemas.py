from __future__ import annotations
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "1.1"

class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")

class Event(Strict):
    event_id: str
    source: str = "wazuh"
    file_name: str
    file_sha256: str
    record_number: int
    raw: dict[str, Any]
    fields: dict[str, Any]
    original_time: str | None
    utc_time: str | None
    timezone_known: bool
    time_warning: str | None = None
    entities: dict[str, list[str]] = Field(default_factory=dict)

class ImportIssue(Strict):
    record_number: int
    code: str
    message: str
    count: int = Field(1, ge=1)

class ImportResult(Strict):
    events: list[Event] = Field(default_factory=list)
    issues: list[ImportIssue] = Field(default_factory=list)
    total_records: int = 0
    duplicate_records: int = 0

    @property
    def rejected_records(self) -> int:
        return sum(issue.count for issue in self.issues if issue.record_number > 0)

    @property
    def file_errors(self) -> int:
        return sum(1 for issue in self.issues if issue.record_number == 0)

class Link(Strict):
    from_event: str
    to_event: str
    rule: str
    reasons: list[str]
    delta_seconds: float

class Case(Strict):
    case_id: str
    events: list[Event]
    links: list[Link] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

class Evidence(Strict):
    event_id: str
    field: str
    value: str | int | float | bool | None

class Finding(Strict):
    technique_id: str = Field(pattern=r"^T[0-9]{4}([.][0-9]{3})?$")
    rationale: str = Field(max_length=300)
    evidence: list[Evidence] = Field(max_length=4)
    source_ids: list[str] = Field(default_factory=list, max_length=3)
    verdict: Literal["unchecked", "supported", "rejected", "analyst_required"] = "unchecked"

class Recommendation(Strict):
    action: Literal["review_process", "collect_logs", "check_account", "confirm_authorization"]
    condition: str = Field(max_length=400)
    evidence: list[Evidence] = Field(default_factory=list, max_length=4)
    status: Literal["unchecked", "supported", "analyst_required", "rejected"] = "unchecked"
    technique_ids: list[str] = Field(default_factory=list, max_length=8)
    source_ids: list[str] = Field(default_factory=list, max_length=3)

class Draft(Strict):
    facts: list[Evidence] = Field(default_factory=list, max_length=4)
    hypotheses: list[str] = Field(default_factory=list, max_length=3)
    techniques: list[Finding] = Field(default_factory=list, max_length=3)
    recommendations: list[Recommendation] = Field(default_factory=list, max_length=2)
    missing: list[str] = Field(default_factory=list, max_length=4)
    abstentions: list[str] = Field(default_factory=list, max_length=4)

class Check(Strict):
    target: str
    code: str
    status: Literal["passed", "failed", "not_checked"]
    detail: str
    needed: list[str] = Field(default_factory=list)

class Chunk(Strict):
    chunk_id: str
    document_id: str
    text: str
    title: str
    source: str
    version: str
    source_sha256: str
    technique_id: str | None = None
    score: float = 0

class Report(Strict):
    run_id: str
    case_id: str
    mode: Literal["A", "B", "C", "D"]
    status: Literal["completed", "partial", "abstained", "technical_error"]
    versions: dict[str, Any]
    facts: list[Evidence] = Field(default_factory=list)
    hypotheses: list[str] = Field(default_factory=list)
    techniques: list[Finding] = Field(default_factory=list)
    recommendations: list[Recommendation] = Field(default_factory=list)
    priority: Literal["high", "medium", "low", "unknown"] = "unknown"
    priority_reasons: list[str] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    links: list[Link] = Field(default_factory=list)
    missing: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    checks: list[Check] = Field(default_factory=list)
    refusals: list[dict[str, Any]] = Field(default_factory=list)
    errors: list[dict[str, str]] = Field(default_factory=list)
    retrieval: dict[str, Any] = Field(default_factory=dict)
    sources: list[Chunk] = Field(default_factory=list)
    durations: dict[str, float] = Field(default_factory=dict)
    environment: dict[str, Any] = Field(default_factory=dict)
    attempts: list[dict[str, Any]] = Field(default_factory=list)
