from __future__ import annotations
import importlib.util
import importlib
import json
import platform
import time
import uuid
from datetime import datetime, timezone
import psutil
from pydantic import ValidationError
from . import __version__
from .config import Settings
from .schemas import SCHEMA_VERSION, Case, Check, Draft, Evidence, Finding, Recommendation, Report
from .retrieval import ALGORITHM, Retriever, SearchError, Snapshot, case_query, file_hash
from .profiles import PROFILE_VERSION, candidates
from .priority import prioritize
from .verification import verify
from .generation import InputBudgetError, LlamaRuntime, ModelUnavailable, ModelTimeoutError, OutputFormatError, GrammarCompileError, build_messages
from .security import analysis_lock, offline_guard
from .storage import Store
from .resources import ResourceSampler
from .correlate import CORRELATION_VERSION

MODES = {"A": "LLM без RAG", "B": "LLM + RAG", "C": "Правила + RAG", "D": "LLM + RAG + верификация"}

def readiness(settings: Settings):
    checks = {}
    snapshot = None
    try:
        snapshot = Snapshot(settings.path("snapshot"))
        checks["snapshot"] = {"ok": True, "sha256": snapshot.sha256, "techniques": len(snapshot.techniques), "provenance": snapshot.provenance}
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        checks["snapshot"] = {"ok": False, "message": "Снимок отсутствует или повреждён"}
    try:
        index = Retriever(settings.path("index"))
        current_runbook = settings.root / "knowledge/runbook.md"
        runbook_hash = file_hash(current_runbook) if current_runbook.exists() else "none"
        valid = bool(snapshot and index.metadata.get("snapshot_sha256") == snapshot.sha256
                     and index.metadata.get("chunk_chars") == str(settings.limits.rag_chunk_chars)
                     and index.metadata.get("runbook_sha256") == runbook_hash
                     and index.metadata.get("algorithm") == ALGORITHM)
        checks["index"] = {"ok": valid, "metadata": index.metadata, "message": "готов" if valid else "Индекс не соответствует данным/конфигурации; перестройте его"}
    except SearchError as exc:
        checks["index"] = {"ok": False, "message": str(exc)}
    checks["model"] = {"ok": settings.model_path.is_file(), "message": str(settings.model_path)}
    try:
        module = importlib.import_module("llama_cpp")
        checks["runtime"] = {"ok": True, "version": module.__version__}
    except (ImportError, OSError, RuntimeError):
        checks["runtime"] = {"ok": False, "message": "CPU-библиотека не установлена или её native-зависимости недоступны"}
    try:
        if not checks["runtime"]["ok"]:
            raise ImportError()
        module.LlamaGrammar.from_json_schema(json.dumps(Draft.model_json_schema()), verbose=False)
        checks["grammar"] = {"ok": True, "schema": SCHEMA_VERSION}
    except Exception:
        checks["grammar"] = {"ok": False, "message": "Строгая грамматика недоступна; скрытый переход к общему JSON запрещён"}
    checks["mode_C_ready"] = checks["snapshot"]["ok"] and checks["index"]["ok"]
    checks["generative_ready"] = checks["mode_C_ready"] and checks["model"]["ok"] and checks["runtime"]["ok"] and checks["grammar"]["ok"]
    return checks

def rule_draft(case: Case, chunks):
    draft = Draft()
    for profile, event, evidence in candidates(case.events):
        source_ids = [chunk.chunk_id for chunk in chunks if chunk.technique_id == profile.technique_id]
        if not source_ids:
            draft.abstentions.append(f"{profile.technique_id}: RAG не вернул определение техники")
            continue
        if any(f.technique_id == profile.technique_id for f in draft.techniques):
            continue
        draft.techniques.append(Finding(technique_id=profile.technique_id, rationale=profile.description,
                                       evidence=evidence, source_ids=source_ids))
        draft.facts.extend(evidence)
    if draft.facts:
        draft.recommendations.append(Recommendation(action="confirm_authorization", condition="Уточнить разрешённость наблюдаемого запуска", evidence=draft.facts[:1]))
    if not draft.techniques:
        draft.abstentions.append("Фиксированные правила не нашли полного набора поддерживаемых признаков и источников")
    draft.missing.append("Разрешённость действий и их результат требуют дополнительного контекста")
    draft.facts = draft.facts[:4]
    draft.techniques = draft.techniques[:3]
    draft.abstentions = draft.abstentions[:4]
    return Draft.model_validate(draft.model_dump())

def environment():
    process = psutil.Process()
    memory = psutil.virtual_memory()
    result = {"os": platform.platform(), "python": platform.python_version(), "cpu": platform.processor(),
              "cpu_logical": psutil.cpu_count(), "memory_total_bytes": memory.total,
              "memory_available_bytes": memory.available, "rss_start_bytes": process.memory_info().rss,
              "created_utc": datetime.now(timezone.utc).isoformat()}
    from pathlib import Path
    for name in ("cpu.max", "memory.max", "memory.current"):
        path = Path("/sys/fs/cgroup") / name
        if path.is_file():
            result["cgroup_" + name.replace(".", "_")] = path.read_text().strip()
    return result

def analyze(case: Case, mode: str, settings: Settings, runtime=None, progress=None, persist=True):
    if mode not in MODES:
        raise ValueError("Неизвестный режим")
    offline_guard()
    with analysis_lock(settings.path("data")):
        return _analyze_locked(case, mode, settings, runtime, progress or (lambda *a: None), persist)

def _analyze_locked(case, mode, settings, runtime, progress, persist):
    started = time.perf_counter()
    report = Report(run_id="run-" + uuid.uuid4().hex, case_id=case.case_id, mode=mode, status="completed",
                    versions={"application": __version__, "schema": SCHEMA_VERSION, "config_sha256": settings.fingerprint,
                              "profiles": PROFILE_VERSION, "correlator": CORRELATION_VERSION, "model_config": settings.model.model_dump(),
                              "inputs": sorted({e.file_sha256 for e in case.events}),
                              "case_sha256": __import__("hashlib").sha256(case.model_dump_json().encode()).hexdigest()},
                    environment=environment(), links=case.links,
                    timeline=[{"event_id": e.event_id, "original_time": e.original_time, "utc_time": e.utc_time,
                               "timezone_known": e.timezone_known, "warning": e.time_warning} for e in case.events],
                    limitations=list(case.warnings) + ["Краткая сводка ограничена 4 фактами и 3 техниками; полный состав событий доступен в случае"] )
    owned_runtime = None
    finished = False
    runtime_was_loaded = bool(getattr(runtime, "model", None))
    sampler = ResourceSampler()
    sampler.start()
    try:
        progress("Проверка готовности", 5)
        if not case.events:
            raise ValueError("Случай не содержит событий")
        ready = readiness(settings)
        if not ready["snapshot"]["ok"]:
            raise SearchError("Снимок ATT&CK отсутствует или повреждён")
        if not ready["index"]["ok"]:
            raise SearchError("Индекс отсутствует, повреждён или устарел")
        snapshot = Snapshot(settings.path("snapshot"))
        report.versions["snapshot_sha256"] = snapshot.sha256
        license_path = settings.root / "docs/licenses/MITRE-ATTACK.txt"
        if license_path.is_file():
            report.versions["knowledge_license"] = license_path.read_text(encoding="utf-8")
        report.versions["snapshot_provenance"] = snapshot.provenance
        report.versions["index"] = ready["index"]["metadata"]
        stage = time.perf_counter()
        report.priority, report.priority_reasons = prioritize(case, settings)
        report.durations["priority"] = time.perf_counter() - stage
        chunks = []
        if mode != "A":
            progress("Поиск источников", 15)
            stage = time.perf_counter()
            query = case_query(case)
            chunks = Retriever(settings.path("index")).search(query, settings.limits.rag_top_k)
            report.sources = chunks
            report.retrieval = {"status": "found" if chunks else "no_results", "query": query,
                                "chunk_ids": [c.chunk_id for c in chunks], "index_version": ready["index"]["metadata"]["index_version"]}
            report.durations["retrieval"] = time.perf_counter() - stage
        else:
            report.retrieval = {"status": "disabled_for_mode_A"}
        stage = time.perf_counter()
        if mode == "C":
            progress("Применение фиксированных правил", 40)
            draft = rule_draft(case, chunks)
        else:
            if runtime is None:
                owned_runtime = LlamaRuntime(settings)
                runtime = owned_runtime
            progress("Локальная генерация на CPU", 35)
            runtime_was_loaded = bool(getattr(runtime, "model", None))
            retrieved_chunks = list(chunks)
            while True:
                try:
                    messages = build_messages(case, chunks, settings.model.max_input_chars)
                    if hasattr(runtime, "check_budget"):
                        runtime.check_budget(messages)
                    break
                except InputBudgetError:
                    if not chunks:
                        raise
                    chunks = chunks[:-1]
            if mode != "A":
                report.retrieval["all_chunks"] = [chunk.model_dump() for chunk in retrieved_chunks]
                report.retrieval["used_chunk_ids"] = [chunk.chunk_id for chunk in chunks]
                report.retrieval["omitted_for_context_budget"] = [c.chunk_id for c in retrieved_chunks if c not in chunks]
                report.sources = chunks
                if len(chunks) < len(retrieved_chunks):
                    report.limitations.append("Часть найденных RAG-фрагментов исключена по бюджету контекста; перечень сохранён в retrieval")
            if hasattr(runtime, "on_token"):
                runtime.on_token = lambda count: progress(f"Генерация на CPU: получено {count} фрагментов ответа", min(70, 35 + count * 35 // settings.model.max_tokens))
            draft = None
            for attempt in range(settings.model.format_retries + 1):
                attempt_started = time.perf_counter()
                attempt_record = {"attempt": attempt + 1, "messages": messages, "raw": None}
                report.attempts.append(attempt_record)
                try:
                    raw = runtime.generate(messages, Draft.model_json_schema())
                    attempt_record["raw"] = raw
                    draft = Draft.model_validate_json(raw)
                    attempt_record["format_valid"] = True
                    break
                except (ValidationError, json.JSONDecodeError):
                    attempt_record["format_valid"] = False
                    # Retry gets the same bounded untrusted input, not an arbitrarily long failed output.
                    messages = messages + [{"role": "user", "content": "Предыдущий ответ не соответствует схеме. Сформируй корректный JSON; не добавляй новые сведения."}]
                finally:
                    attempt_record["seconds"] = time.perf_counter() - attempt_started
                    if attempt_record["raw"] is None and getattr(runtime, "last_partial", ""):
                        attempt_record["raw"] = runtime.last_partial
            report.durations["model_load"] = 0.0 if runtime_was_loaded else runtime.load_seconds
            report.versions["runtime"] = runtime.metadata
            if draft is None:
                raise OutputFormatError("Все разрешённые попытки формирования схемы исчерпаны")
        report.durations["generation_or_rules"] = time.perf_counter() - stage
        # Never trust statuses supplied by the LLM in A/B/C.
        for finding in draft.techniques:
            finding.verdict = "unchecked"
        for rec in draft.recommendations:
            rec.status = "unchecked"
        if mode == "D":
            progress("Проверка доказательств", 80)
            stage = time.perf_counter()
            draft, report.checks, report.refusals = verify(draft, case, snapshot, chunks)
            report.durations["verification"] = time.perf_counter() - stage
            supported = any(f.verdict == "supported" for f in draft.techniques)
            if report.refusals:
                report.status = "partial" if supported or draft.facts else "abstained"
            elif not supported:
                report.status = "partial" if any(f.verdict == "analyst_required" for f in draft.techniques) or not draft.abstentions else "abstained"
            if not draft.techniques and not draft.abstentions:
                report.checks.append(Check(target="analysis", code="missing_conclusion", status="failed",
                    detail="Модель не предложила заключения и не обосновала отказ; это недостаток ответа, а не подтверждённая недостаточность событий",
                    needed=["Повторная проверка аналитиком; не считать такой ответ корректным отказом"]))
                report.status = "partial"
                report.limitations.append("Ответ модели не содержит заключения и обоснованного отказа; это недостаток результата")
            report.limitations.append("Содержательная проверка ограничена тремя профилями Sysmon; гипотезы требуют аналитика")
        else:
            report.limitations.append("Доказательная постпроверка режима D не применялась; выводы не считаются верифицированными")
            if not draft.techniques:
                report.status = "abstained" if draft.abstentions else "partial"
                if not draft.abstentions:
                    report.limitations.append("Модель не сформировала содержательного заключения и не обосновала отказ")
        report.facts, report.hypotheses, report.techniques = draft.facts, draft.hypotheses, draft.techniques
        report.recommendations, report.missing = draft.recommendations, draft.missing
        report.refusals.extend({"target": "model_or_rules", "code": "declared_abstention", "reason": text, "needed": [],
                                "verification": "rule_condition" if mode == "C" else "model_declared_not_semantically_verified"} for text in draft.abstentions)
        if draft.abstentions and mode == "D":
            report.checks.append(Check(target="declared_abstentions", code="declared_abstention_not_verified", status="not_checked",
                detail="Самостоятельные текстовые отказы модели не доказаны; проверенные отказы представлены отдельными кодами условий профиля"))
        report.limitations.append("Отнесение наблюдаемого поведения к ATT&CK не доказывает успешность атаки или злонамеренность")
        finished = True
    except (Exception, KeyboardInterrupt) as exc:
        if isinstance(exc, KeyboardInterrupt):
            code = "cancelled"
        elif isinstance(exc, SearchError):
            code = "retrieval_failure"
            report.retrieval["status"] = "technical_error"
        elif isinstance(exc, ModelUnavailable): code = "model_unavailable"
        elif isinstance(exc, InputBudgetError): code = "input_budget"
        elif isinstance(exc, ModelTimeoutError): code = "model_timeout"
        elif isinstance(exc, GrammarCompileError): code = "schema_grammar_unsupported"
        elif isinstance(exc, OutputFormatError): code = "format_error"
        elif isinstance(exc, ValueError): code = "invalid_input_or_configuration"
        else: code = "analysis_failure"
        # No raw logs or arbitrary exception text in diagnostic output.
        safe = str(exc) if isinstance(exc, (SearchError, ModelUnavailable, InputBudgetError, ModelTimeoutError, GrammarCompileError)) else type(exc).__name__
        report.errors.append({"code": code, "message": safe})
        report.status = "technical_error"
    finally:
        if not finished and not report.errors:
            report.status = "technical_error"
            report.errors.append({"code": "interrupted", "message": "Анализ прерван до формирования итогового результата"})
        if runtime is not None:
            import copy
            report.versions["runtime"] = copy.deepcopy(runtime.metadata)
            report.durations.setdefault("model_load", 0.0 if runtime_was_loaded else runtime.load_seconds)
        report.environment.update(sampler.stop())
        if owned_runtime:
            owned_runtime.close()
        report.durations["total"] = time.perf_counter() - started
        memory = psutil.Process().memory_info()
        report.environment["rss_end_bytes"] = memory.rss
        if hasattr(memory, "peak_wset"):
            report.environment["os_peak_working_set_bytes"] = memory.peak_wset
        if persist:
            store = Store(settings.path("data"))
            store.save_case(case)
            store.save_report(report)
        progress("Завершено", 100)
    return report
