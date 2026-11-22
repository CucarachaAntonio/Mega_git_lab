"""Bounded local Wazuh / Suricata import with source-exact addressing."""
from __future__ import annotations
import hashlib
import json
import re
from io import StringIO
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter
from .config import Limits
from .schemas import Event, FieldOrigin, TimeMark, ImportIssue, ImportResult
from .evidence import pointer

NORMALIZATION_VERSION = "source-pointers-no-labels-2.0"
LABEL_KEYS = {"mitre", "attack", "attack_id", "mitre_id", "technique_id", "technique", "techniques", "tactic", "tactics", "expected", "gold", "labels", "ground_truth", "expected_techniques"}
ATTACK_CODE = re.compile(r"\bT[0-9]{4}(?:[.][0-9]{3})?\b", re.I)
ROOTS = {"timestamp", "id", "agent", "manager", "rule", "data", "full_log", "location", "decoder"}
EVE_ROOTS = {"timestamp", "event_type", "flow_id", "tx_id", "src_ip", "dest_ip", "src_port", "dest_port", "proto", "app_proto", "alert", "dns", "http", "tls", "flow", "host", "sensor_name", "in_iface", "community_id"}

def _validate_tree(value, limits: Limits, depth=0):
    if depth > limits.max_depth: raise ValueError("Превышена допустимая вложенность")
    if isinstance(value, str) and len(value) > limits.max_field_chars: raise ValueError("Превышена допустимая длина поля")
    if isinstance(value, dict):
        for key, child in value.items():
            if len(key) > 128: raise ValueError("Слишком длинное имя поля")
            _validate_tree(child, limits, depth + 1)
    if isinstance(value, list):
        if len(value) > 256: raise ValueError("Слишком длинный массив")
        for child in value: _validate_tree(child, limits, depth + 1)

def flatten_with_paths(record, roots=ROOTS):
    leaves, excluded, annotation_paths = [], {}, {}
    def visit(value, parts):
        flat = ".".join(map(str, parts))
        if isinstance(value, dict):
            for key, child in value.items():
                if key.lower() in LABEL_KEYS or key.lower().startswith(("mitre_", "expected_", "gold_", "ground_truth")) or ATTACK_CODE.search(key):
                    reason = "explicit_attack_code_hint" if ATTACK_CODE.search(key) else "source_annotation"
                    excluded[".".join(map(str, [*parts, key]))] = reason
                    annotation_paths[pointer([*parts, key])] = reason
                else: visit(child, [*parts, key])
        elif isinstance(value, list):
            for i, child in enumerate(value): visit(child, [*parts, i])
        elif isinstance(value, str) and ATTACK_CODE.search(value):
            excluded[flat] = "explicit_attack_code_hint"
            annotation_paths[pointer(parts)] = "explicit_attack_code_hint"
        else: leaves.append((flat, pointer(parts), value))
    for key, value in record.items():
        if key in roots: visit(value, [key])
    counts = Counter(flat for flat, _, _ in leaves)
    fields, paths = {}, {}
    for flat, path, value in leaves:
        name = path if counts[flat] > 1 else flat
        fields[name] = value; paths[name] = path
    return fields, paths, excluded, annotation_paths

def flatten(record: dict):
    return flatten_with_paths(record)[0]

def parse_time(value):
    if not value: return None, False, "missing"
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        known = parsed.tzinfo is not None and parsed.utcoffset() is not None and not value.endswith("-00:00")
        return (parsed.astimezone(timezone.utc).isoformat(), True, "comparable") if known else (None, False, "unknown_timezone")
    except (ValueError, OverflowError): return None, False, "invalid"

def normalize(record: dict, filename: str, file_hash: str, position: int, limits: Limits) -> Event:
    _validate_tree(record, limits)
    source = "suricata" if isinstance(record.get("event_type"), str) and "rule" not in record else "wazuh"
    if source == "wazuh":
        if not isinstance(record.get("rule"), dict) or type(record["rule"].get("id")) not in (str, int): raise ValueError("Обязательно поле rule.id")
        if not isinstance(record.get("agent"), dict) or type(record["agent"].get("id")) not in (str, int) or not record["agent"]["id"]: raise ValueError("Обязательно поле agent.id типа string/int")
    if source == "suricata" and not record["event_type"].strip(): raise ValueError("Обязательно непустое event_type")
    canonical = json.dumps(record, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    event_id = "ev-" + hashlib.sha256(canonical.encode()).hexdigest()[:24]
    native_id = record.get("id")
    record_id = str(native_id) if type(native_id) in (str, int) else event_id
    sensor = record.get("sensor_name") or record.get("host")
    source_id = ("wazuh:agent:" + str(record["agent"]["id"])) if source == "wazuh" else ("suricata:sensor:" + sensor if isinstance(sensor, str) and sensor else "suricata:file:" + file_hash[:16])
    manager = record.get("manager", {})
    if source == "wazuh" and isinstance(manager, dict) and isinstance(manager.get("name"), str):
        source_id = "wazuh:manager:" + manager["name"] + ":agent:" + str(record["agent"]["id"])
    original = record.get("timestamp")
    if original is not None and not isinstance(original, str): raise ValueError("timestamp должен быть строкой либо отсутствовать")
    utc_time, known, state = parse_time(original)
    fields, paths, excluded, annotation_paths = flatten_with_paths(record, ROOTS if source == "wazuh" else EVE_ROOTS)
    marks = [TimeMark(field="timestamp", original=original, utc=utc_time, timezone_known=known, role="alert" if source == "wazuh" else "event")]
    for field in ("data.win.system.systemTime", "data.win.eventdata.utcTime"):
        value = fields.get(field)
        if isinstance(value, str):
            stamp, zone, _ = parse_time(value)
            marks.append(TimeMark(field=field, original=value, utc=stamp, timezone_known=zone, role="event"))
    secondary = [m for m in marks[1:] if m.role == "event"]
    comparable = [datetime.fromisoformat(m.utc) for m in secondary if m.utc]
    if len(comparable) > 1 and (max(comparable) - min(comparable)).total_seconds() > 1:
        state = "conflicting"
    elif secondary and any(m.utc is None for m in secondary): state = "incomparable"
    messages = {"missing": "Время отсутствует; порядок не установлен", "invalid": "Время не распознано; порядок не установлен", "unknown_timezone": "Часовой пояс неизвестен; межсобытийный порядок не установлен", "conflicting": "Конфликт отметок времени действия; хронология неопределённа", "incomparable": "Отметки времени действия несопоставимы; хронология неопределённа"}
    entities = {}
    for name, value in fields.items():
        if type(value) not in (str, int) or str(value).strip().lower() in {"", "-", "unknown", "n/a"}: continue
        key = name.lower(); kind = None
        if key.endswith(("srcip", "dstip", "_ip", "ipaddress")): kind = "ip"
        elif key.endswith(("username", "user", "subjectusername", "targetusername")): kind = "account"
        elif key.endswith(("commandline", "command_line")): kind = "command"
        elif key.endswith(("image", "processname", "process_name")): kind = "process"
        elif key.endswith(("hostname", "computer", "agent.name")): kind = "host"
        elif key.endswith(("domain", "queryname", "rrname")): kind = "domain"
        if kind and str(value) not in entities.setdefault(kind, []): entities[kind].append(str(value))
    return Event(event_id=event_id, source=source, source_id=source_id, record_id=record_id,
        record_id_kind="native" if type(native_id) in (str, int) else "content_hash",
        file_name=Path(filename).name, file_sha256=file_hash, record_number=position, raw=record, fields=fields,
        field_origins={name: FieldOrigin(source_id=source_id, record_id=record_id, json_pointer=path) for name, path in paths.items()},
        source_annotations={path: FieldOrigin(source_id=source_id, record_id=record_id, json_pointer=path,
                                            origin=reason) for path, reason in annotation_paths.items()},
        excluded_fields=excluded, original_time=original, utc_time=utc_time, timezone_known=known,
        time_state=state, timestamps=marks, time_warning=messages.get(state), entities=entities)

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
