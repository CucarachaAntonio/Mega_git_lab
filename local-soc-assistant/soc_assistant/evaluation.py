"""Independent output evaluator. Does not import verification/profiles or alter reports."""
from __future__ import annotations
import csv
import hashlib
import json
import statistics
from pathlib import Path
from .schemas import Case, Report

PRIORITY_RANK = {"low": 0, "medium": 1, "high": 2}

def _ratio(numerator, denominator):
    return numerator / denominator if denominator else None

def evaluate(report: Report, case: Case, gold: dict):
    predicted_findings = [finding for finding in report.techniques if finding.verdict != "rejected"]
    predicted = {f.technique_id for f in predicted_findings}
    expected = set(gold["techniques"])
    events = {e.event_id: e for e in case.events}
    def valid(ref):
        event = events.get(ref.event_id)
        if not event or ref.field not in event.fields: return False
        observed = event.fields[ref.field]
        return type(observed) is type(ref.value) and observed == ref.value
    fact_valid = sum(valid(ref) for ref in report.facts)
    evidence_total = sum(len(f.evidence) for f in predicted_findings)
    evidence_valid = sum(valid(ref) for f in predicted_findings for ref in f.evidence)
    complete = 0
    unsupported = 0
    for finding in predicted_findings:
        by_event = {}
        for ref in finding.evidence:
            if valid(ref): by_event.setdefault(ref.event_id, set()).add(ref.field)
        enough = any(set(gold["required_evidence_fields"]) <= fields for fields in by_event.values())
        complete += enough
        unsupported += (finding.technique_id not in expected or not enough or not all(valid(ref) for ref in finding.evidence))
    technical = report.status == "technical_error"
    refused = not technical and not predicted and bool(report.refusals or report.status == "abstained")
    expected_refusal = bool(gold["should_abstain"])
    priority_error = "correct" if report.priority == gold["priority"] else "unknown_mismatch"
    if report.priority in PRIORITY_RANK and gold["priority"] in PRIORITY_RANK:
        delta = PRIORITY_RANK[report.priority] - PRIORITY_RANK[gold["priority"]]
        priority_error = "over" if delta > 0 else "under" if delta < 0 else "correct"
    return {"run_id": report.run_id, "scenario_id": gold["scenario_id"], "mode": report.mode,
            "tp": len(predicted & expected), "fp": len(predicted - expected), "fn": len(expected - predicted),
            "technical_error": int(technical), "refusal_tp": int(refused and expected_refusal),
            "refusal_fp": int(refused and not expected_refusal), "refusal_fn": int(not refused and expected_refusal),
            "sufficient_cases": int(not expected_refusal), "priority_error": priority_error,
            "fact_total": len(report.facts), "fact_valid": fact_valid,
            "evidence_total": evidence_total, "evidence_valid": evidence_valid,
            "technique_claims": len(predicted_findings), "evidence_complete_claims": complete,
            "unsupported_technique_claims": unsupported, "structured_claims": len(report.facts) + len(predicted_findings),
            "unsupported_structured_claims": len(report.facts) - fact_valid + unsupported,
            "content_answer": int(not technical and bool(predicted)),
            "partial_facts": int(not technical and bool(report.facts)),
            "empty_answer": int(not technical and not report.facts and not predicted),
            "seconds": report.durations.get("total"), "model_load_seconds": report.durations.get("model_load", 0),
            "manual_rationale_correctness": None, "manual_recommendation_correctness": None}

def aggregate(rows: list[dict]):
    result = {}
    for mode in sorted({row["mode"] for row in rows}):
        group = [r for r in rows if r["mode"] == mode]
        sums = {key: sum(r[key] for r in group) for key in ("tp", "fp", "fn", "refusal_tp", "refusal_fp", "refusal_fn", "sufficient_cases", "fact_total", "fact_valid", "evidence_total", "evidence_valid", "technique_claims", "evidence_complete_claims", "unsupported_technique_claims", "structured_claims", "unsupported_structured_claims")}
        tp, fp, fn = sums["tp"], sums["fp"], sums["fn"]
        times = [r["seconds"] for r in group if r["seconds"] is not None and not r["technical_error"]]
        result[mode] = {"attempts": len(group), **sums, "precision": _ratio(tp, tp + fp), "recall": _ratio(tp, tp + fn),
                        "f1": _ratio(2 * tp, 2 * tp + fp + fn),
                        "refusal_precision": _ratio(sums["refusal_tp"], sums["refusal_tp"] + sums["refusal_fp"]),
                        "refusal_recall": _ratio(sums["refusal_tp"], sums["refusal_tp"] + sums["refusal_fn"]),
                        "unjustified_refusal_rate": _ratio(sums["refusal_fp"], sums["sufficient_cases"]),
                        "fact_reference_accuracy": _ratio(sums["fact_valid"], sums["fact_total"]),
                        "evidence_completeness": _ratio(sums["evidence_complete_claims"], sums["technique_claims"]),
                        "unsupported_structured_claim_rate": _ratio(sums["unsupported_structured_claims"], sums["structured_claims"]),
                        "unsupported_technique_claim_rate": _ratio(sums["unsupported_technique_claims"], sums["technique_claims"]),
                        "coverage": sum(r["content_answer"] for r in group) / len(group),
                        "partial_fact_coverage": sum(r["partial_facts"] for r in group) / len(group),
                        "technical_error_rate": sum(r["technical_error"] for r in group) / len(group),
                        "priority_accuracy": sum(r["priority_error"] == "correct" for r in group) / len(group),
                        "priority_over": sum(r["priority_error"] == "over" for r in group),
                        "priority_under": sum(r["priority_error"] == "under" for r in group),
                        "priority_unknown_mismatch": sum(r["priority_error"] == "unknown_mismatch" for r in group),
                        "empty_answers": sum(r["empty_answer"] for r in group),
                        "mean_seconds_successful": statistics.mean(times) if times else None,
                        "median_seconds_successful": statistics.median(times) if times else None,
                        "manual_rationale_correctness": None, "manual_recommendation_correctness": None}
    return result

def experiment(settings, modes, repeats, split, output: Path, limit=None, scenario_ids=None):
    # Gold enters only this orchestration/evaluation layer, never the analyzer.
    from .generation import LlamaRuntime
    from .ingest import import_bytes
    from .correlate import build_cases
    from .service import _analyze_locked
    from .security import analysis_lock, offline_guard
    offline_guard()
    gold_path = settings.root / "evaluation/gold.json"
    gold_bytes = gold_path.read_bytes()
    gold = json.loads(gold_bytes)
    scenarios = [s for s in gold["scenarios"] if split == "all" or s["split"] == split]
    if scenario_ids:
        scenarios = [s for s in scenarios if s["scenario_id"] in scenario_ids]
    scenarios = scenarios[:limit] if limit else scenarios
    if not scenarios: raise ValueError("Нет выбранных сценариев")
    if any(m in modes for m in ("A", "B", "D")) and repeats < 3:
        raise ValueError("Для генеративных режимов нужны минимум три повтора")
    output.mkdir(parents=True, exist_ok=True)
    plan = {"modes": modes, "repeats": repeats, "split": split, "scenarios": [s["scenario_id"] for s in scenarios],
            "gold_sha256": hashlib.sha256(gold_bytes).hexdigest(), "config_sha256": settings.fingerprint,
            "schema_version": __import__("soc_assistant.schemas", fromlist=["SCHEMA_VERSION"]).SCHEMA_VERSION,
            "prompt_state_reset_per_generation": True,
            "memory_note": "Shared experiment keeps LLM weights resident during C; run C separately for standalone RSS",
            "warning": "Engineering corpus only; no statistical superiority claim. Manual fields unfilled."}
    (output / "plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
    rows = []
    with analysis_lock(settings.path("data")):
        runtime = LlamaRuntime(settings) if any(m in modes for m in ("A", "B", "D")) else None
        try:
            for scenario in scenarios:
                content = (settings.root / scenario["input"]).read_bytes()
                if hashlib.sha256(content).hexdigest() != scenario["sha256"]:
                    raise ValueError("Хеш сценария не совпал с зафиксированным эталоном")
                imported = import_bytes(content, scenario["input"], settings.limits)
                cases = build_cases(imported.events, settings.limits, settings.correlation.enabled)
                if imported.issues or len(cases) != 1:
                    raise ValueError("Сценарий должен давать ровно один случай без ошибок импорта")
                case = cases[0]
                for mode in modes:
                    for repeat in range(repeats if mode != "C" else 1):
                        print(f"{scenario['scenario_id']} {mode} repeat {repeat + 1}", flush=True)
                        report = _analyze_locked(case, mode, settings, runtime if mode != "C" else None, lambda *args: None, True)
                        (output / (report.run_id + ".json")).write_text(report.model_dump_json(indent=2), encoding="utf-8")
                        row = evaluate(report, case, scenario)
                        row["repeat"] = repeat + 1
                        rows.append(row)
                        # Persist individual results incrementally, including failures.
                        (output / "individual.json").write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
                        if any(error["code"] == "cancelled" for error in report.errors):
                            raise KeyboardInterrupt()
        except KeyboardInterrupt:
            plan["status"] = "cancelled"
            (output / "plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
            (output / "summary.json").write_text(json.dumps(aggregate(rows), ensure_ascii=False, indent=2), encoding="utf-8")
            raise
        finally:
            if runtime: runtime.close()
    summary = aggregate(rows)
    (output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    with (output / "analyst-review.csv").open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["run_id", "scenario_id", "rationale_correct_0_or_1", "recommendation_correct_0_or_1", "notes"])
        writer.writerows([r["run_id"], r["scenario_id"], "", "", ""] for r in rows)
    return summary
