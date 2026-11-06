from __future__ import annotations
import json
import os
from pathlib import Path
import streamlit as st
from .config import load_settings
from .correlate import build_cases
from .export import PRIORITIES, render_html
from .ingest import import_bytes
from .security import BusyError, offline_guard
from .service import MODES, analyze, readiness
from .storage import Store

ACTIONS = {"review_process": "Проверить процесс", "collect_logs": "Запросить журналы", "check_account": "Проверить учётную запись", "confirm_authorization": "Уточнить разрешённость"}
STATUSES = {"completed": "завершён", "partial": "частичный результат", "abstained": "отказ от заключения", "technical_error": "техническая ошибка"}
VERDICTS = {"unchecked": "Без доказательной постпроверки", "supported": "Профиль подтверждён", "rejected": "Вывод отклонён", "analyst_required": "Нужен аналитик"}

def show_event(event):
    st.text(f"{event.event_id} · {event.file_name} · запись {event.record_number}")
    if event.time_warning: st.warning(event.time_warning)
    st.json(event.fields, expanded=False)
    with st.expander("Исходная запись — только для аудита, включая исключённые метки"):
        st.json(event.raw)
    st.caption(f"SHA-256 файла: {event.file_sha256}")

def show_report(report, case, prefix="report"):
    col1, col2, col3 = st.columns(3)
    col1.metric("Приоритет проверки", PRIORITIES[report.priority])
    col2.metric("Режим", report.mode)
    col3.metric("Время, с", f"{report.durations.get('total', 0):.2f}")
    st.caption(f"Статус: {STATUSES[report.status]} · {report.run_id}")
    for reason in report.priority_reasons: st.write("• " + reason)
    if report.errors:
        st.error("Анализ завершился технической ошибкой. Это не доказательный отказ.")
        st.json(report.errors)
    facts_tab, techniques_tab, rec_tab, checks_tab, provenance_tab = st.tabs(["Факты и гипотезы", "ATT&CK", "Рекомендации и отказ", "Проверки", "Источники и версии"])
    events = {event.event_id: event for event in case.events} if case else {}
    with facts_tab:
        st.subheader("Факты: значения полей")
        if report.mode != "D": st.info("Заявленные факты не проходили доказательную постпроверку режима D.")
        if not report.facts: st.write("Нет фактов в ответе.")
        for index, fact in enumerate(report.facts):
            st.code(f"{fact.field} = {fact.value}", language=None)
            st.text(fact.event_id)
            if st.button(f"Открыть событие #{index + 1}", key=f"{prefix}-fact-{report.run_id}-{index}"):
                if fact.event_id in events: show_event(events[fact.event_id])
                else: st.error("Ссылка на событие недействительна")
        st.subheader("Гипотезы — требуют проверки аналитиком")
        for text in report.hypotheses: st.text(text)
        st.subheader("Временная линия")
        st.dataframe(report.timeline, hide_index=True, use_container_width=True)
        with st.expander("Основания связывания"):
            st.json([link.model_dump() for link in report.links])
    with techniques_tab:
        if not report.techniques: st.write("Техники не предложены.")
        for index, finding in enumerate(report.techniques):
            with st.expander(f"{finding.technique_id} · {VERDICTS[finding.verdict]}", expanded=True):
                st.text(finding.rationale)
                st.json([ref.model_dump() for ref in finding.evidence])
                for ref in finding.evidence:
                    if ref.event_id in events:
                        with st.expander(f"Событие {ref.event_id}"):
                            st.text(ref.field)
                            show_event(events[ref.event_id])
                for identifier in finding.source_ids:
                    source = next((c for c in report.sources if c.chunk_id == identifier), None)
                    if source:
                        with st.expander("Открыть фрагмент источника"):
                            st.text(identifier); st.text(source.text); st.text(source.source)
                    else:
                        st.warning("Ссылка на источник недействительна")
                        st.text(identifier)
    with rec_tab:
        for rec in report.recommendations:
            st.write(ACTIONS[rec.action] + " · " + ("Основание проверено, применён локальный шаблон" if rec.status == "supported" else VERDICTS[rec.status]))
            st.text(rec.condition)
            st.json([ref.model_dump() for ref in rec.evidence], expanded=False)
        if report.refusals:
            st.subheader("Отказы и недопустимые выводы")
            for refusal in report.refusals:
                st.warning("Вывод ограничен или отклонён")
                st.text(f"{refusal['target']}: {refusal['reason']}")
                st.write("Нужно:", ", ".join(refusal.get("needed", [])) or "см. основание отказа")
        st.subheader("Недостающие сведения")
        for item in report.missing: st.text(item)
        st.subheader("Ограничения")
        for item in report.limitations: st.text(item)
    with checks_tab:
        st.json([check.model_dump() for check in report.checks])
        st.json(report.durations)
    with provenance_tab:
        st.json(report.versions, expanded=False)
        st.json(report.environment, expanded=False)
        st.json(report.retrieval)
        for source_index, chunk in enumerate(report.sources, 1):
            with st.expander(f"Источник {source_index}"):
                st.text(chunk.chunk_id); st.text(chunk.text); st.json(chunk.model_dump(exclude={"text"}))
        with st.expander("Первоначальные ответы модели и попытки исправления"):
            for attempt in report.attempts:
                st.code(attempt.get("raw") or "Ответ не получен", language="json")
    left, right = st.columns(2)
    left.download_button("Скачать JSON", report.model_dump_json(indent=2), file_name=report.run_id + ".json", mime="application/json", key=prefix + report.run_id + "json")
    right.download_button("Скачать HTML", render_html(report, case), file_name=report.run_id + ".html", mime="text/html", key=prefix + report.run_id + "html")

def main():
    st.set_page_config(page_title="Локальный ассистент ИБ", page_icon="🛡", layout="wide")
    offline_guard()
    settings = load_settings(os.environ.get("SOC_CONFIG", str(Path(__file__).resolve().parents[1] / "config.toml")))
    store = Store(settings.path("data"))
    st.title("Локальный ассистент анализа событий ИБ")
    st.caption("Исследовательский прототип · MITRE ATT&CK · данные обрабатываются локально")
    ready = readiness(settings)
    with st.sidebar:
        st.subheader("Готовность")
        for key, title in [("snapshot", "Снимок ATT&CK"), ("index", "Индекс знаний"), ("model", "GGUF-модель"), ("runtime", "CPU-рантайм"), ("grammar", "Грамматика отчёта")]:
            st.write(("✓ " if ready[key]["ok"] else "○ ") + title)
        st.info("Режим C доступен без LLM. Установка и обновления выполняются отдельно.")
        st.caption("Один локальный пользователь · одна задача анализа одновременно")
    upload_tab, analyze_tab, history_tab, compare_tab = st.tabs(["Импорт и события", "Анализ случая", "История", "Сравнение режимов"])
    with upload_tab:
        st.subheader("Загрузка Wazuh alerts.json / JSONL")
        uploaded = st.file_uploader("Выберите файл UTF-8", type=["json", "jsonl"], help=f"До {settings.limits.upload_mb} МБ")
        col1, col2 = st.columns(2)
        import_clicked = col1.button("Импортировать файл", disabled=uploaded is None)
        demo_clicked = col2.button("Загрузить демонстрационный случай")
        if import_clicked or demo_clicked:
            content = (settings.root / "examples/demo.jsonl").read_bytes() if demo_clicked else uploaded.getvalue()
            name = "demo.jsonl" if demo_clicked else uploaded.name
            result = import_bytes(content, name, settings.limits)
            if len(content) <= settings.limits.upload_mb * 1024 * 1024:
                store.save_import(content, name, result)
            imported_cases = build_cases(result.events, settings.limits, settings.correlation.enabled)
            for case in imported_cases: store.save_case(case)
            st.session_state["recent_case_ids"] = [case.case_id for case in imported_cases]
            st.session_state["import_result"] = result
        result = st.session_state.get("import_result")
        if result:
            notice = st.warning if result.issues else st.success
            notice(f"Принято: {len(result.events)} · Отклонено записей: {result.rejected_records} · Ошибок файла: {result.file_errors} · Повторов: {result.duplicate_records}")
            if result.issues: st.dataframe([issue.model_dump() for issue in result.issues], hide_index=True)
            if result.events:
                chosen = st.selectbox("Просмотреть событие", range(len(result.events)), format_func=lambda i: result.events[i].event_id)
                show_event(result.events[chosen])
        with st.expander("История импортов"):
            st.dataframe([{"файл": item["filename"], "принято": len(item["result"]["events"]), "отклонено": sum(issue.get("count", 1) for issue in item["result"]["issues"] if issue["record_number"] > 0), "ошибок файла": sum(issue["record_number"] == 0 for issue in item["result"]["issues"]), "sha256": item["sha256"]} for item in store.imports()], hide_index=True)
    cases = store.cases()
    with analyze_tab:
        if not cases:
            st.info("Загрузите файл или демонстрационный случай на вкладке импорта.")
        else:
            recent = st.session_state.get("recent_case_ids", [])
            recent_only = st.checkbox("Только случаи последней загрузки", value=True) if recent else False
            available_cases = [case for case in cases if case.case_id in recent] if recent_only else cases
            case_index = st.selectbox("Случай", range(len(available_cases)), format_func=lambda i: f"{available_cases[i].case_id} · {available_cases[i].events[0].file_name} · событий: {len(available_cases[i].events)}")
            case = available_cases[case_index]
            with st.expander("Состав случая и неопределённости"):
                for warning in case.warnings: st.warning(warning)
                for event in case.events:
                    with st.expander(event.event_id): show_event(event)
            mode = st.selectbox("Режим анализа", list(MODES), index=2, format_func=lambda key: key + " · " + MODES[key])
            available = ready["mode_C_ready"] if mode == "C" else ready["generative_ready"]
            if not available: st.warning("Режим не готов. Выполните команды подготовки из README.")
            if st.button("Запустить локальный анализ", type="primary", disabled=not available):
                bar = st.progress(0, text="Подготовка")
                try:
                    report = analyze(case, mode, settings, progress=lambda text, value: bar.progress(value, text=text))
                    st.session_state["last_report"] = report
                except BusyError as exc: st.warning(str(exc))
            last = st.session_state.get("last_report")
            if last and last.case_id == case.case_id: show_report(last, case, "current")
    reports = store.reports()
    with history_tab:
        if not reports: st.info("Сохранённых анализов пока нет.")
        else:
            index = st.selectbox("Сохранённый анализ", range(len(reports)), format_func=lambda i: f"{reports[i].mode} · {reports[i].case_id} · {reports[i].run_id[-8:]}")
            report = reports[index]
            case = next((case for case in cases if case.case_id == report.case_id), None)
            show_report(report, case, "history")
    with compare_tab:
        st.caption("Сравнение сохранённых запусков. Полный эксперимент с эталонами запускается отдельной CLI-командой.")
        if reports:
            ids = sorted({r.case_id for r in reports})
            selected = st.selectbox("Сравнить случай", ids)
            st.dataframe([{"режим": r.mode, "запуск": r.run_id[-8:], "статус": STATUSES[r.status], "приоритет": PRIORITIES[r.priority],
                           "техники": ", ".join(f.technique_id for f in r.techniques if f.verdict != "rejected"),
                           "отказы": len(r.refusals), "ошибки": len(r.errors), "секунды": round(r.durations.get("total", 0), 3)} for r in reports if r.case_id == selected], hide_index=True, use_container_width=True)
        else: st.info("Запустите один случай в нескольких режимах.")
