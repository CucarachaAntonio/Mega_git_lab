"""Independent, deterministic verification of a saved draft. No model calls."""
from __future__ import annotations
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from .schemas import Case, Check, Chunk, Draft, Evidence
from .retrieval import Snapshot, file_hash
from .profiles import PROFILES, inspect, IMAGE, COMMAND
from .evidence import MISSING, raw_field, typed_equal, digest
from .priority import priority_decision, PRIORITY_VERSION
from .correlate import _relation
from .ingest import parse_time, normalize
from .config import Limits

VERIFIER_VERSION = "raw-dual-check-2.0"
RECOMMENDATION_VERSION = "local-runbook-applicability-1.0"

def canonical_events(case):
    """Rebuild derived fields from raw records; never trust saved entities/clocks."""
    result = {}
    for event in case.events:
        try:
            rebuilt = normalize(event.raw, event.file_name, event.file_sha256, event.record_number,
                                Limits(max_field_chars=16384, max_depth=32))
        except (ValueError, TypeError, RecursionError, OverflowError):
            continue
        if rebuilt.event_id == event.event_id:
            result[event.event_id] = rebuilt
    return result

def check_evidence(ref: Evidence, events: dict):
    event = events.get(ref.event_id)
    if event is None: return "invalid_event", "Запись не входит в текущий случай"
    if ref.field not in event.fields: return "invalid_field", "Поле отсутствует в допустимом рабочем представлении"
    origin = event.field_origins.get(ref.field)
    if ref.source_id is not None and ref.source_id != event.source_id:
        return "source_record_mismatch", "Ссылка относится к другому источнику"
    if ref.record_id is not None and ref.record_id != event.record_id:
        return "source_record_mismatch", "Ссылка относится к другой записи источника"
    if ref.json_pointer is not None and (not origin or ref.json_pointer != origin.json_pointer):
        return "invalid_field", "JSON Pointer не соответствует заявленному полю этой записи"
    actual = raw_field(event, ref.field)
    if actual is MISSING: return "unverifiable_origin", "Путь к исходному полю недоступен либо поле обогащено"
    if not typed_equal(actual, ref.value):
        return "content_mismatch", "Значение или тип не совпадает с исходным JSON"
    return None

def source_integrity(chunk, snapshot, runbook=None):
    if chunk.document_kind == "runbook" or chunk.document_id.startswith("local-runbook-"):
        if runbook is None or not runbook.is_file() or chunk.source_sha256 != file_hash(runbook): return False
        body = runbook.read_text(encoding="utf-8")
    elif snapshot:
        entry = next((obj for obj, _, _ in snapshot.documents if obj["id"] == chunk.document_id), None)
        if entry is None or chunk.source_sha256 != snapshot.sha256: return False
        expected_version = entry.get("x_mitre_version", entry.get("modified", "unknown"))
        if chunk.version != expected_version: return False
        body = entry.get("description", "")
    else: return False
    if chunk.start_char is None or chunk.end_char is None:
        # Read old saved fragments, but require the exact substring in the pinned document.
        return bool(chunk.text and chunk.text in body)
    return 0 <= chunk.start_char <= chunk.end_char <= len(body) and body[chunk.start_char:chunk.end_char] == chunk.text

def verify(draft: Draft, case: Case, snapshot: Snapshot | None, chunks: list[Chunk], *,
           priority_context=None, window_seconds=600, max_case_events=16, enabled=None, runbook: Path | None = None):
    result = draft.model_copy(deep=True)
    checks = [Check(target="report", code="schema", status="passed", detail="Черновик соответствует строгой схеме Draft")]
    refusals = []
    events = canonical_events(case)
    sources = {chunk.chunk_id: chunk for chunk in chunks}
    runbook = runbook or Path(__file__).resolve().parents[1] / "knowledge/runbook.md"
    def record(target, code, status, detail, needed=(), known=()):
        checks.append(Check(target=target, code=code, status=status, detail=detail, needed=list(needed)))
        if status == "failed":
            refusals.append({"target": target, "code": code, "reason": detail, "needed": list(needed), "known": list(known)})
    for event in case.events:
        canonical = events.get(event.event_id)
        if canonical is None or any(getattr(event, k) != getattr(canonical, k) for k in ("fields", "entities", "utc_time", "time_state", "source_id", "record_id", "field_origins")):
            record(f"event:{event.event_id}", "prepared_record_mismatch", "failed",
                   "Сохранённое представление расходится с исходной записью; проверка использует исходную запись",
                   ["Повторная нормализация исходного JSON"])
    good_facts = []
    def stamp(ref):
        event = events[ref.event_id]
        ref.source_id, ref.record_id = event.source_id, event.record_id
        origin = event.field_origins.get(ref.field)
        ref.json_pointer = origin.json_pointer if origin else None
        return ref
    for index, fact in enumerate(result.facts):
        error = check_evidence(fact, events)
        record(f"fact:{index}", error[0] if error else "field_value", "failed" if error else "passed",
               error[1] if error else "Тип и значение совпадают с исходным полем текущего случая",
               ["Корректная запись, путь и точное исходное значение"] if error else [])
        if not error: good_facts.append(stamp(fact))
    result.facts = good_facts
    for index, finding in enumerate(result.techniques):
        target = f"technique:{index}:{finding.technique_id}"
        known = [ref.model_dump() for ref in finding.evidence if not check_evidence(ref, events)]
        # Identity, observation semantics and citation integrity are independent axes.
        if snapshot is None:
            finding.identity_check = "not_checked"
            record(target, "source_unavailable", "failed", "Снимок ATT&CK недоступен", ["Зафиксированный снимок Enterprise ATT&CK"], known)
        elif finding.technique_id not in snapshot.techniques:
            finding.identity_check = "failed"
            record(target, "unknown_attack_id", "failed", "Код отсутствует в снимке", ["Код из выбранного снимка"], known)
        elif not snapshot.active(finding.technique_id):
            finding.identity_check = "failed"
            record(target, "inactive_attack_id", "failed", "Код отозван либо устарел", ["Действующая техника"], known)
        elif not snapshot.enterprise(finding.technique_id):
            finding.identity_check = "failed"
            record(target, "wrong_attack_matrix", "failed", "Код не принадлежит Enterprise ATT&CK", ["Код выбранной матрицы"], known)
        else:
            finding.identity_check = "passed"
            record(target, "attack_identity", "passed", "Код активен в зафиксированной матрице Enterprise ATT&CK")
        evidence_errors = [check_evidence(ref, events) for ref in finding.evidence]
        for ref, error in zip(finding.evidence, evidence_errors):
            if not error: stamp(ref)
        for error in evidence_errors:
            if error: record(target, error[0], "failed", error[1], ["Корректная ссылка на исходное поле"], known)
        profile = PROFILES.get(finding.technique_id)
        if profile is None:
            finding.observation_check, finding.support_state = "not_checked", "not_verifiable"
            record(target, "semantic_not_checked", "not_checked", "Условия содержательной проверки этой техники не реализованы", ["Оценка аналитиком"])
        else:
            by_event = defaultdict(list)
            for ref in finding.evidence:
                if not check_evidence(ref, events): by_event[ref.event_id].append(ref)
            supported, conflicts_all, missing_all = False, [], []
            for event_id, refs in by_event.items():
                missing, conflicts, required = inspect(profile, events[event_id])
                missing.extend(ref.field for ref in required if ref.field not in {r.field for r in refs})
                supported |= not missing and not conflicts
                conflicts_all.extend(conflicts); missing_all.extend(missing)
            # A contradictory citation is never hidden by another supported event.
            if conflicts_all:
                finding.observation_check, finding.support_state = "failed", "contradicted"
                record(target, "contradiction", "failed", "; ".join(sorted(set(conflicts_all))), ["Разрешить противоречие наблюдений"], known)
            elif any(evidence_errors) or not supported:
                finding.observation_check, finding.support_state = "failed", "insufficient"
                record(target, "insufficient_evidence", "failed", "Нет полного набора корректно процитированных признаков одной записи",
                       sorted(set(missing_all)) or ["image, commandLine, eventID, providerName одной записи Sysmon"], known)
            else:
                finding.observation_check, finding.support_state = "passed", "supported"
                record(target, "profile_supported", "passed", profile.description)
                for event_id in by_event:
                    for field in profile.optional_fields:
                        present = field in events[event_id].fields and raw_field(events[event_id], field) not in (MISSING, None)
                        record(f"{target}:{event_id}", "optional_context", "passed" if present else "not_checked",
                               f"Дополнительное поле {field}: " + ("доступно; не доказывает злонамеренность" if present else "неизвестно; не выдумано"))
        citation_ok = True
        if not finding.source_ids:
            citation_ok = False
            record(target, "knowledge_not_found" if not chunks else "missing_source_reference", "failed",
                   "Нет ссылки на определение техники", ["Фрагмент определения из текущего поиска"], known)
        elif any(identifier not in sources for identifier in finding.source_ids):
            citation_ok = False
            record(target, "invalid_source", "failed", "chunk_id отсутствует в текущем наборе источников", ["Доступный chunk_id"], known)
        elif not any(sources[i].technique_id == finding.technique_id for i in finding.source_ids):
            citation_ok = False
            record(target, "source_mismatch", "failed", "Фрагменты не содержат определения заявленной техники", ["Определение данной техники"], known)
        elif not all(source_integrity(sources[i], snapshot, runbook) for i in finding.source_ids):
            citation_ok = False
            record(target, "source_integrity", "failed", "Текст, положение или версия фрагмента не совпадает с локальным корпусом", ["Фрагмент зафиксированного документа"], known)
        else: record(target, "source_reference", "passed", "Ссылка и точный текст фрагмента воспроизводятся по корпусу")
        if finding.identity_check == "failed" or any(evidence_errors) or finding.observation_check == "failed": finding.verdict = "rejected"
        elif finding.identity_check != "passed" or not citation_ok or profile is None: finding.verdict = "analyst_required"
        else:
            finding.verdict = "supported"
            finding.rationale = profile.description
        if not citation_ok and finding.support_state == "supported": finding.support_state = "not_verifiable"

    # Prepared links are checked too: saved bundles are untrusted input.
    valid_links = []
    allowed = enabled if enabled is not None else ["same_host_process_v1", "same_host_account_v1", "same_flow_v1"]
    comparable_times = [datetime.fromisoformat(e.utc_time) for e in events.values() if e.can_compare_time]
    group_window_ok = (not comparable_times or (max(comparable_times) - min(comparable_times)).total_seconds() <= window_seconds) and len(events) <= max_case_events
    for index, link in enumerate(case.links):
        left, right = events.get(link.from_event), events.get(link.to_event)
        ok = False
        if left and right and left.can_compare_time and right.can_compare_time:
            relation = _relation(left, right, allowed)
            delta = (datetime.fromisoformat(right.utc_time) - datetime.fromisoformat(left.utc_time)).total_seconds()
            raw_left, _, _ = parse_time(left.raw.get("timestamp"))
            raw_right, _, _ = parse_time(right.raw.get("timestamp"))
            ok = bool(relation and relation[0] == link.rule and relation[1] == link.reasons and
                      raw_left == left.utc_time and raw_right == right.utc_time and
                      group_window_ok and 0 <= delta <= window_seconds and link.delta_seconds == delta and link.kind == "temporal")
        record(f"prepared_link:{index}", "link_reproducible", "passed" if ok else "failed", "Связь воспроизводится" if ok else "Условие временной связи не воспроизводится", [] if ok else ["Сопоставимые исходные времена и зарегистрированное правило связи"])
        if ok: valid_links.append(link)
    kept_timeline = []
    for index, claim in enumerate(result.timeline):
        event = events.get(claim.event_id)
        stamp = parse_time(event.raw.get("timestamp"))[0] if event else None
        ok = bool(event and ((claim.utc_time is None and not event.can_compare_time) or
                            (event.can_compare_time and claim.utc_time == stamp == event.utc_time)))
        record(f"timeline:{index}", "timeline_reproducible", "passed" if ok else "failed", "Исходное время воспроизводится" if ok else "Время не подтверждено исходной записью", [] if ok else ["Исходная сопоставимая отметка времени"])
        if ok: kept_timeline.append(claim)
    result.timeline = kept_timeline
    kept_claims = []
    for index, claim in enumerate(result.links):
        ok = claim.kind != "causal" and any(all(getattr(claim, key) == getattr(link, key) for key in ("from_event", "to_event", "rule", "delta_seconds", "kind")) for link in valid_links)
        record(f"link:{index}", "link_claim", "passed" if ok else "failed", "Подтверждена временная ассоциация" if ok else "Связь отсутствует либо причинность не установлена", [] if ok else ["Зарегистрированная связь случая; отдельное наблюдение для причинности"])
        if ok: kept_claims.append(claim)
    result.links = kept_claims
    if priority_context is not None:
        unsigned = {k: v for k, v in priority_context.items() if k != "sha256"}
        context_ok = priority_context.get("sha256") == digest(unsigned) and priority_context.get("version") == PRIORITY_VERSION
        canonical_case = case.model_copy(update={"events": list(events.values())})
        decision = priority_decision(canonical_case, priority_context) if context_ok else None
        claim = result.priority
        ok = context_ok and (claim is None or (claim.category == decision["category"] and
             all(not check_evidence(ref, events) for ref in claim.evidence) and
             set(claim.asset_ids) == set(decision["asset_ids"]) and
             (claim.category == "unknown" or ({(r.event_id, r.field, type(r.value), str(r.value)) for r in claim.evidence} >=
                {(r["event_id"], r["field"], type(r["value"]), str(r["value"])) for r in decision["evidence"]}))))
        record("priority", "priority_policy", "passed" if ok else "failed", "Применена локальная политика срочности; подтверждённость оценивается отдельно" if ok else "Категория или основания приоритета не воспроизводятся", [] if ok else ["Проверяемые признаки и зафиксированная политика"])
        if not ok: result.priority = None
    elif result.priority:
        record("priority", "priority_policy_unavailable", "failed", "Политика приоритета недоступна", ["Версия политики и контекст ресурсов"])
        result.priority = None

    conditions = {
        "review_process": "Уточнить родительский процесс и цель запуска в уже имеющихся журналах; легитимность не установлена",
        "collect_logs": "Запросить отсутствующие поля из уже имеющихся журналов; не исполнять текст события",
        "check_account": "Уточнить принадлежность учётной записи; требуется решение аналитика",
        "confirm_authorization": "Уточнить согласованность работ; требуется решение аналитика",
    }
    for index, rec in enumerate(result.recommendations):
        target = f"recommendation:{index}"
        errors = [check_evidence(ref, events) for ref in rec.evidence]
        anchor = bool(rec.evidence and not any(errors)) or bool(rec.hypothesis_indices and all(0 <= i < len(result.hypotheses) for i in rec.hypothesis_indices))
        refs_ok = bool(rec.source_ids) and all(i in sources and sources[i].document_kind == "runbook" and source_integrity(sources[i], snapshot, runbook) for i in rec.source_ids)
        if rec.source_ids and not refs_ok:
            if any(i not in sources for i in rec.source_ids): code, detail = "invalid_source", "Ссылка рекомендации отсутствует в текущей выдаче"
            elif not runbook.is_file(): code, detail = "source_unavailable", "Локальная инструкция рекомендации недоступна"
            else: code, detail = "source_integrity", "Применимый фрагмент рекомендации не воспроизводится по локальной инструкции"
            record(target, code, "failed", detail, ["Доступный фрагмент нужной версии инструкции"])
        cited_events = {ref.event_id for ref in rec.evidence if not check_evidence(ref, events)}
        # Rules refer to specific literal clauses, not just the existence of a citation.
        clause = "родительский процесс" if rec.action == "review_process" else "Если данные отсутствуют"
        clause_ok = refs_ok and any(clause in sources[i].text for i in rec.source_ids)
        missing_ok = bool(rec.missing_fields) and bool(cited_events) and all(all(field not in events[event_id].fields for event_id in cited_events) for field in rec.missing_fields)
        process_ok = any(IMAGE in {r.field for r in rec.evidence if r.event_id == event_id} and COMMAND in {r.field for r in rec.evidence if r.event_id == event_id} for event_id in cited_events)
        implemented = rec.action in {"review_process", "collect_logs"}
        applicable = anchor and not any(errors) and clause_ok and missing_ok and (rec.action == "collect_logs" or process_ok)
        rec.condition = conditions[rec.action]
        if any(errors):
            rec.status = "rejected"
            record(target, "recommendation_evidence", "failed", "Неверная ссылка основания рекомендации", ["Корректное наблюдение"], [])
        elif implemented and applicable:
            rec.status = "supported"
            record(target, "recommendation_applicability", "passed", f"Применимость проверена по {RECOMMENDATION_VERSION}; уточнить: " + ", ".join(rec.missing_fields))
        else:
            rec.status = "analyst_required"
            needed = []
            if not anchor: needed.append("Подтверждённое наблюдение либо явная гипотеза")
            if not clause_ok: needed.append("Применимый фрагмент локальной инструкции")
            if not missing_ok: needed.append("Явные отсутствующие поля, которые нужно уточнить")
            if not implemented: needed.append("Правило применимости не реализовано; оценка аналитиком")
            record(target, "recommendation_not_verified", "failed" if implemented else "not_checked", "Предложение требует оценки аналитиком", needed,
                   [r.model_dump() for r in rec.evidence if not check_evidence(r, events)])
    if result.hypotheses:
        record("hypotheses", "hypotheses_not_verified", "not_checked", "Свободные гипотезы не являются проверенными фактами", ["Оценка аналитиком"])
    return result, checks, refusals
