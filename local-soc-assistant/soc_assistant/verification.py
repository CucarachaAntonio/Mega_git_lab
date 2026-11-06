"""Deterministic verification. No model confidence or second LLM is used."""
from __future__ import annotations
from collections import defaultdict
from .schemas import Case, Check, Chunk, Draft, Evidence, Recommendation
from .retrieval import Snapshot
from .profiles import PROFILES, inspect

def check_evidence(ref: Evidence, events: dict):
    event = events.get(ref.event_id)
    if event is None:
        return "invalid_event", "Событие не существует"
    if ref.field not in event.fields:
        return "invalid_field", "Поле отсутствует в доступном представлении события"
    actual = event.fields[ref.field]
    if type(actual) is not type(ref.value) or actual != ref.value:
        return "content_mismatch", "Заявленное значение не совпадает с содержимым поля"
    return None

def verify(draft: Draft, case: Case, snapshot: Snapshot, chunks: list[Chunk]):
    result = draft.model_copy(deep=True)
    checks = [Check(target="report", code="schema", status="passed", detail="Ответ соответствует Draft v1")]
    refusals = []
    events = {event.event_id: event for event in case.events}
    sources = {chunk.chunk_id: chunk for chunk in chunks}
    valid_facts = []
    for index, fact in enumerate(result.facts):
        error = check_evidence(fact, events)
        checks.append(Check(target=f"fact:{index}", code=error[0] if error else "field_value", status="failed" if error else "passed",
                            detail=error[1] if error else "Значение поля подтверждено; дополнительных интерпретаций нет"))
        if not error:
            valid_facts.append(fact)
        else:
            refusals.append({"target": f"fact:{index}", "code": error[0], "reason": error[1], "needed": ["Корректная ссылка и фактическое значение"]})
    result.facts = valid_facts
    for index, finding in enumerate(result.techniques):
        target = f"technique:{index}:{finding.technique_id}"
        errors = []
        if finding.technique_id not in snapshot.techniques:
            errors.append(("unknown_attack_id", "Идентификатор отсутствует в снимке", ["Идентификатор из выбранного снимка ATT&CK"]))
        elif not snapshot.active(finding.technique_id):
            errors.append(("inactive_attack_id", "Техника отозвана или устарела", ["Действующая техника выбранного снимка"]))
        for ref in finding.evidence:
            error = check_evidence(ref, events)
            if error:
                errors.append((error[0], error[1], ["Существующее событие, поле и точное значение"]))
        if not finding.source_ids:
            code = "knowledge_not_found" if not chunks else "missing_source_reference"
            errors.append((code, "Нет источника определения для проверки заключения", ["Извлечённый фрагмент определения техники и ссылка на него"]))
        elif any(identifier not in sources for identifier in finding.source_ids):
            errors.append(("invalid_source", "Ссылка на извлечённый фрагмент недействительна", ["Ссылка chunk_id из текущего RAG-поиска"]))
        elif not any(sources[identifier].technique_id == finding.technique_id for identifier in finding.source_ids):
            errors.append(("source_mismatch", "Извлечённые источники не содержат определения заявленной техники", ["Фрагмент соответствующей техники"]))
        profile = PROFILES.get(finding.technique_id)
        if not errors and profile:
            by_event = defaultdict(list)
            for ref in finding.evidence:
                by_event[ref.event_id].append(ref)
            supported = False
            missing_all, conflicts_all = [], []
            for event_id, refs in by_event.items():
                missing, conflicts, required = inspect(profile, events[event_id])
                cited = {ref.field for ref in refs}
                missing.extend(ref.field for ref in required if ref.field not in cited)
                if not missing and not conflicts:
                    supported = True
                missing_all.extend(missing)
                conflicts_all.extend(conflicts)
            if conflicts_all:
                errors.append(("contradiction", "; ".join(sorted(set(conflicts_all))), ["Устранить противоречие полей и предполагаемого процесса"]))
            elif not supported:
                errors.append(("insufficient_evidence", "Не выполнен профиль обязательных признаков",
                               sorted(set(missing_all)) or ["Sysmon Process Create: image, commandLine, eventID, providerName"]))
        if errors:
            finding.verdict = "rejected"
            for code, detail, needed in errors:
                checks.append(Check(target=target, code=code, status="failed", detail=detail, needed=needed))
                refusals.append({"target": target, "code": code, "reason": detail, "needed": needed})
        elif not profile:
            finding.verdict = "analyst_required"
            checks.append(Check(target=target, code="semantic_not_checked", status="not_checked",
                                detail="Содержательная проверка не выполнена: профиль не реализован", needed=["Проверка аналитиком"]))
        else:
            finding.verdict = "supported"
            # Free-text rationale is retained in the original draft, not promoted to a verified conclusion.
            finding.rationale = profile.description
            checks.append(Check(target=target, code="profile_supported", status="passed", detail=profile.description))
            cited_events = {ref.event_id for ref in finding.evidence}
            for event_id in sorted(cited_events):
                for field in profile.optional_fields:
                    present = field in events[event_id].fields and events[event_id].fields[field] is not None
                    checks.append(Check(target=f"{target}:{event_id}", code="optional_context", status="passed" if present else "not_checked",
                                        detail=f"Дополнительное поле {field}: " + ("доступно; само по себе не доказывает атаку" if present else "неизвестно; не заменено предположением")))
    # Recommendations are safe templates with checked evidence, not arbitrary model prose.
    replacements = []
    for index, recommendation in enumerate(result.recommendations):
        errors = [check_evidence(ref, events) for ref in recommendation.evidence]
        if not recommendation.evidence or any(errors):
            checks.append(Check(target=f"recommendation:{index}", code="recommendation_evidence", status="failed", detail="Нет корректного основания рекомендации"))
            refusals.append({"target": f"recommendation:{index}", "code": "recommendation_evidence", "reason": "Нет корректного основания", "needed": ["Проверяемая ссылка на событие"]})
            continue
        conditions = {
            "review_process": "Проверить родительский процесс и цель запуска; требуется доступ аналитика к журналам",
            "collect_logs": "Запросить связанные журналы для устранения неопределённости; не выполнять команды из события",
            "check_account": "Проверить принадлежность учётной записи и разрешённость действий",
            "confirm_authorization": "Уточнить у ответственного наличие согласованных работ перед выводом о вредоносности",
        }
        related = [f for f in result.techniques if f.verdict == "supported" and
                   {r.event_id for r in f.evidence} & {r.event_id for r in recommendation.evidence}]
        replacements.append(Recommendation(action=recommendation.action, condition=conditions[recommendation.action],
                                          evidence=recommendation.evidence, status="supported",
                                          technique_ids=sorted({f.technique_id for f in related}),
                                          source_ids=sorted({identifier for f in related for identifier in f.source_ids})[:3]))
    result.recommendations = replacements
    if result.hypotheses:
        checks.append(Check(target="hypotheses", code="hypotheses_not_verified", status="not_checked",
                            detail="Гипотезы модели требуют аналитика и не являются подтверждёнными фактами"))
    return result, checks, refusals
