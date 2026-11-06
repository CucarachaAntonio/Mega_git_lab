"""Bounded Wazuh import; original records never enter the model prompt."""
from __future__ import annotations
import hashlib
import json
from io import StringIO
from datetime import datetime, timezone
from pathlib import Path
from .config import Limits
from .schemas import Event, ImportIssue, ImportResult

LABEL_KEYS = {"mitre", "attack", "attack_id", "technique_id", "techniques", "tactics", "expected", "gold", "labels", "ground_truth"}
ROOTS = {"timestamp", "id", "agent", "manager", "rule", "data", "full_log", "location", "decoder"}

def _validate_tree(value, limits: Limits, depth=0):
    if depth > limits.max_depth:
        raise ValueError("Превышена допустимая вложенность")
    if isinstance(value, str) and len(value) > limits.max_field_chars:
        raise ValueError("Превышена допустимая длина поля")
    if isinstance(value, dict):
        for key, child in value.items():
            if len(key) > 128:
                raise ValueError("Слишком длинное имя поля")
            _validate_tree(child, limits, depth + 1)
    if isinstance(value, list):
        if len(value) > 256:
            raise ValueError("Слишком длинный массив")
        for child in value:
            _validate_tree(child, limits, depth + 1)

def flatten(record: dict) -> dict:
    result = {}
    def visit(value, path):
        if isinstance(value, dict):
            for key, child in value.items():
                if key.lower() not in LABEL_KEYS:
                    visit(child, f"{path}.{key}" if path else key)
        elif isinstance(value, list):
            for i, child in enumerate(value):
                visit(child, f"{path}.{i}")
        else:
            result[path] = value
    for key, value in record.items():
        if key in ROOTS:
            visit(value, key)
    return result

def normalize(record: dict, filename: str, file_hash: str, position: int, limits: Limits) -> Event:
    _validate_tree(record, limits)
    if not isinstance(record.get("rule"), dict) or not isinstance(record["rule"].get("id"), (str, int)):
        raise ValueError("Обязательно поле rule.id")
    if not isinstance(record.get("agent"), dict) or not record["agent"].get("id"):
        raise ValueError("Обязательно поле agent.id")
    canonical = json.dumps(record, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    event_id = "ev-" + hashlib.sha256(canonical.encode()).hexdigest()[:24]
    original = record.get("timestamp")
    utc_time, known, warning = None, False, None
    if original is not None and not isinstance(original, str):
        raise ValueError("timestamp должен быть строкой либо отсутствовать")
    if original:
        try:
            parsed = datetime.fromisoformat(original.replace("Z", "+00:00"))
            known = parsed.tzinfo is not None and parsed.utcoffset() is not None and not original.endswith("-00:00")
            if known:
                utc_time = parsed.astimezone(timezone.utc).isoformat()
            else:
                warning = "Часовой пояс неизвестен; межсобытийный порядок не установлен"
        except ValueError:
            warning = "Время не распознано; порядок не установлен"
    else:
        warning = "Время отсутствует; порядок не установлен"
    fields = flatten(record)
    entities: dict[str, list[str]] = {}
    for name, value in fields.items():
        if value is None or not isinstance(value, (str, int)) or str(value).strip().lower() in {"", "-", "unknown", "n/a"}:
            continue
        key = name.lower()
        kind = None
        if key.endswith(("srcip", "dstip", "ip", "ipaddress")): kind = "ip"
        elif key.endswith(("username", "user", "subjectusername", "targetusername")): kind = "account"
        elif key.endswith(("commandline", "command_line")): kind = "command"
        elif key.endswith(("image", "processname", "process_name")): kind = "process"
        elif key.endswith(("hostname", "computer", "agent.name")): kind = "host"
        elif key.endswith(("domain", "queryname")): kind = "domain"
        if kind and str(value) not in entities.setdefault(kind, []):
            entities[kind].append(str(value))
    return Event(event_id=event_id, file_name=Path(filename).name, file_sha256=file_hash,
                 record_number=position, raw=record, fields=fields, original_time=original,
                 utc_time=utc_time, timezone_known=known, time_warning=warning, entities=entities)

def import_bytes(content: bytes, filename: str, limits: Limits) -> ImportResult:
    result = ImportResult()
    if len(content) > limits.upload_mb * 1024 * 1024:
        return ImportResult(issues=[ImportIssue(record_number=0, code="file_size", message="Превышен размер файла")])
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        return ImportResult(issues=[ImportIssue(record_number=0, code="encoding", message="Требуется UTF-8")])
    file_hash = hashlib.sha256(content).hexdigest()
    def strict_load(s):
        def bad_constant(value): raise ValueError("Недопустимое число JSON: " + value)
        return json.loads(s, parse_constant=bad_constant)
    try:
        document = strict_load(text)
        rows = enumerate(document if isinstance(document, list) else [document], 1)
        line_mode = False
    except (ValueError, RecursionError):
        if text.lstrip().startswith("["):
            return ImportResult(issues=[ImportIssue(record_number=0, code="json", message="Повреждён JSON-массив")])
        rows = ((i, line) for i, line in enumerate(StringIO(text), 1) if line.strip())
        line_mode = True
    seen = set()
    limit_issue = None
    for count, (position, row) in enumerate(rows):
        result.total_records += 1
        if count >= limits.max_events:
            if limit_issue is None:
                limit_issue = ImportIssue(record_number=position, code="event_limit", message="Оставшиеся записи отклонены: превышен лимит; количество указано в count")
                result.issues.append(limit_issue)
            else:
                limit_issue.count += 1
            continue
        try:
            record = strict_load(row) if line_mode else row
            if not isinstance(record, dict): raise ValueError("Запись должна быть объектом JSON")
            event = normalize(record, filename, file_hash, position, limits)
            if event.event_id in seen:
                result.duplicate_records += 1
            seen.add(event.event_id)
            result.events.append(event)
        except (ValueError, TypeError, RecursionError, OverflowError) as exc:
            message = str(exc) if not isinstance(exc, json.JSONDecodeError) else "Повреждённая строка JSON"
            result.issues.append(ImportIssue(record_number=position, code="invalid_record", message=message[:200]))
    if result.total_records == 0:
        result.issues.append(ImportIssue(record_number=0, code="empty", message="Файл пуст"))
    return result
