"""Independent output evaluator. Does not import verification/profiles or alter reports."""
from __future__ import annotations
import csv
import hashlib
import json
import statistics
import time
import uuid
from pathlib import Path
from .schemas import Case, Report
from .evidence import MISSING, resolve, typed_equal

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
        # Independent raw addressing: do not accept cached normalized values or a verifier verdict.
        if ref.field.startswith("/"):
            observed = resolve(event.raw, ref.field)
        else:
            observed = event.raw
            for key in ref.field.split("."):
                if isinstance(observed, dict): observed = observed.get(key, MISSING)
                elif isinstance(observed, list) and key.isdecimal() and int(key) < len(observed): observed = observed[int(key)]
                else: observed = MISSING; break
        origin = event.field_origins.get(ref.field)
        return (observed is not MISSING and typed_equal(observed, ref.value)
                and (ref.source_id is None or ref.source_id == event.source_id)
                and (ref.record_id is None or ref.record_id == event.record_id)
                and (ref.json_pointer is None or bool(origin and ref.json_pointer == origin.json_pointer)))
    fact_valid = sum(valid(ref) for ref in report.facts)
    evidence_total = sum(len(f.evidence) for f in predicted_findings)
    evidence_valid = sum(valid(ref) for f in predicted_findings for ref in f.evidence)
    complete = 0
    unsupported = 0
    for finding in predicted_findings:
        by_event = {}
        for ref in finding.evidence:
            if valid(ref): by_event.setdefault(ref.event_id, set()).add(ref.field)
        required = next((o.get("required_evidence_fields", gold["required_evidence_fields"]) for o in gold.get("opportunities", [])
                         if o.get("technique_id") == finding.technique_id), gold["required_evidence_fields"])
        enough = any(set(required) <= fields for fields in by_event.values())
        complete += enough
        unsupported += (finding.technique_id not in expected or not enough or not all(valid(ref) for ref in finding.evidence))
    technical = report.status == "technical_error"
    refused = not technical and not predicted and bool(report.refusals or report.status == "abstained")
    expected_refusal = bool(gold["should_abstain"])
    priority_error = "correct" if report.priority == gold["priority"] else "unknown_mismatch"
    if report.priority in PRIORITY_RANK and gold["priority"] in PRIORITY_RANK:
        delta = PRIORITY_RANK[report.priority] - PRIORITY_RANK[gold["priority"]]
        priority_error = "over" if delta > 0 else "under" if delta < 0 else "correct"
    opportunities = gold.get("opportunities", [{"technique_id": t, "expected": "conclude"} for t in sorted(expected)])
    if not opportunities and expected_refusal:
        opportunities = [{"technique_id": None, "expected": "abstain"}]
    claim_outcomes = []
    for opportunity in opportunities:
        tid = opportunity.get("technique_id")
        offered = (tid in predicted) if tid else bool(predicted)
        has_refusal = any(r.get("code") not in {"declared_abstention"} and
                          (tid is None or r.get("target", "").endswith(":" + tid)) for r in report.refusals)
        # A specific explicit model abstention is an output decision; gold determines correctness.
        has_refusal |= any(r.get("code") == "declared_abstention" and (tid is None or tid in r.get("reason", "")) for r in report.refusals)
        decision_refused = has_refusal or (tid is None and refused)
        claim_outcomes.append({**opportunity, "conclusion_issued": offered,
            "refusal_issued": not offered and bool(decision_refused),
            "correct_refusal": not offered and bool(decision_refused) and opportunity["expected"] == "abstain",
            "excess_refusal": not offered and bool(decision_refused) and opportunity["expected"] == "conclude"})
    assertion_outcomes = []
    for assertion in gold.get("assertions", []):
        matching_events = [e.event_id for e in case.events if e.record_number == assertion["record_number"]]
        issued = any(ref.event_id in matching_events and ref.field == assertion["field"] and
                     typed_equal(ref.value, assertion["value"]) and valid(ref) for ref in report.facts)
        assertion_outcomes.append({**assertion, "issued_as_fact": issued})
    return {"run_id": report.run_id, "scenario_id": gold["scenario_id"], "mode": report.mode,
            "tp": len(predicted & expected), "fp": len(predicted - expected), "fn": len(expected - predicted),
            "technical_error": int(technical), "refusal_tp": int(refused and expected_refusal),
            "refusal_fp": int(refused and not expected_refusal), "refusal_fn": int(not refused and expected_refusal),
            "sufficient_cases": int(not expected_refusal), "priority_error": priority_error, "predicted_priority": report.priority,
            "fact_total": len(report.facts), "fact_valid": fact_valid,
            "evidence_total": evidence_total, "evidence_valid": evidence_valid,
            "technique_claims": len(predicted_findings), "evidence_complete_claims": complete,
            "unsupported_technique_claims": unsupported, "structured_claims": len(report.facts) + len(predicted_findings),
            "unsupported_structured_claims": len(report.facts) - fact_valid + unsupported,
            "content_answer": int(not technical and bool(predicted)),
            "partial_facts": int(not technical and bool(report.facts)),
            "empty_answer": int(not technical and not report.facts and not predicted),
            "seconds": report.durations.get("total"), "model_load_seconds": report.durations.get("model_load", 0),
            "assertion_opportunities": len(assertion_outcomes), "assertion_issued": sum(a["issued_as_fact"] for a in assertion_outcomes),
            "assertion_outcomes": assertion_outcomes,
            "confirmed_technique_claims": sum(f.verdict == "supported" for f in predicted_findings),
            "candidate_technique_claims": sum(f.verdict == "analyst_required" for f in predicted_findings),
            "claim_opportunities": len(claim_outcomes), "claim_conclusions": sum(o["conclusion_issued"] for o in claim_outcomes),
            "claim_refusals": sum(o["refusal_issued"] for o in claim_outcomes),
            "claim_correct_refusals": sum(o["correct_refusal"] for o in claim_outcomes),
            "claim_excess_refusals": sum(o["excess_refusal"] for o in claim_outcomes),
            "claim_expected_refusals": sum(o["expected"] == "abstain" for o in claim_outcomes),
            "claim_sufficient": sum(o["expected"] == "conclude" for o in claim_outcomes),
            "claim_outcomes": claim_outcomes, "draft_id": report.draft_id,
            "draft_reused": report.measurement.get("draft_reused", False),
            "verification_seconds": report.durations.get("verification"),
            "full_pass_seconds": report.durations.get("full_pass"),
            "latency_origin": report.measurement.get("latency_origin"),
            "generation_backend": report.versions.get("runtime", {}).get("backend"),
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
        counters = dict(sums)
        counters.update({key: sum(r.get(key, 0) for r in group) for key in (
            "claim_opportunities", "claim_conclusions", "claim_refusals", "claim_correct_refusals", "claim_excess_refusals", "claim_expected_refusals", "claim_sufficient", "assertion_opportunities", "assertion_issued", "confirmed_technique_claims", "candidate_technique_claims")})
        count = len(group)
        pairs = {
            "precision": (tp, tp + fp), "recall": (tp, tp + fn), "f1": (2 * tp, 2 * tp + fp + fn),
            "refusal_precision": (sums["refusal_tp"], sums["refusal_tp"] + sums["refusal_fp"]),
            "refusal_recall": (sums["refusal_tp"], sums["refusal_tp"] + sums["refusal_fn"]),
            "unjustified_refusal_rate": (sums["refusal_fp"], sums["sufficient_cases"]),
            "fact_reference_accuracy": (sums["fact_valid"], sums["fact_total"]),
            "evidence_reference_accuracy": (sums["evidence_valid"], sums["evidence_total"]),
            "evidence_completeness": (sums["evidence_complete_claims"], sums["technique_claims"]),
            "unsupported_structured_claim_rate": (sums["unsupported_structured_claims"], sums["structured_claims"]),
            "unsupported_technique_claim_rate": (sums["unsupported_technique_claims"], sums["technique_claims"]),
            "coverage": (sum(r["content_answer"] for r in group), count),
            "partial_fact_coverage": (sum(r["partial_facts"] for r in group), count),
            "technical_error_rate": (sum(r["technical_error"] for r in group), count),
            "priority_accuracy": (sum(r["priority_error"] == "correct" for r in group), count),
            "priority_coverage": (sum(r.get("predicted_priority") != "unknown" for r in group), count),
            "technique_opportunity_coverage": (counters["claim_conclusions"], counters["claim_opportunities"]),
            "annotated_fact_coverage": (counters["assertion_issued"], counters["assertion_opportunities"]),
            "confirmed_technique_share": (counters["confirmed_technique_claims"], sums["technique_claims"]),
            "claim_refusal_precision": (counters["claim_correct_refusals"], counters["claim_refusals"]),
            "claim_refusal_recall": (counters["claim_correct_refusals"], counters["claim_expected_refusals"]),
            "claim_excess_refusal_rate": (counters["claim_excess_refusals"], counters["claim_sufficient"]),
        }
        result[mode]["metrics"] = {name: {"numerator": n, "denominator": d, "value": _ratio(n, d), "applicable": bool(d)} for name, (n, d) in pairs.items()}
        result[mode]["counters"] = counters
        for name, pair in result[mode]["metrics"].items(): result[mode][name] = pair["value"]
        full = [r.get("full_pass_seconds") for r in group if r.get("full_pass_seconds") is not None]
        verification = [r.get("verification_seconds") for r in group if r.get("verification_seconds") is not None]
        result[mode]["timing"] = {"full_pass": {"sum_seconds": sum(full), "count": len(full), "mean_seconds": _ratio(sum(full), len(full))},
                                  "verification": {"sum_seconds": sum(verification), "count": len(verification), "mean_seconds": _ratio(sum(verification), len(verification))},
                                  "full_pass_may_be_composed": any(r.get("draft_reused") for r in group),
                                  "successful_analysis": {"sum_seconds": sum(times), "count": len(times), "samples_seconds": times}}
    return result

def experiment(settings, modes, repeats, split, output: Path, limit=None, scenario_ids=None, replay_dir=None, gold_path_override=None):
    # Gold enters only this orchestration/evaluation layer, never the analyzer.
    from .generation import LlamaRuntime
    from .ingest import import_bytes
    from .correlate import build_cases
    from .service import _analyze_locked
    from .replay import load_bundle, SavedDraftRuntime
    from .storage import Store
    from .security import analysis_lock, offline_guard
    offline_guard()
    gold_path = Path(gold_path_override) if gold_path_override else settings.root / "evaluation/gold.json"
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
            "gold_sha256": hashlib.sha256(gold_bytes).hexdigest(), "dataset_version": gold["version"], "config_sha256": settings.fingerprint,
            "schema_version": __import__("soc_assistant.schemas", fromlist=["SCHEMA_VERSION"]).SCHEMA_VERSION,
            "prompt_state_reset_per_generation": True, "paired_B_D_same_draft": True,
            "experiment_kind": "saved_draft_mechanics" if replay_dir else "local_model",
            "generation_quality_evaluated": replay_dir is None and any(m in modes for m in "ABD"),
            "memory_note": "Shared experiment keeps LLM weights resident during C; run C separately for standalone RSS",
            "warning": "Engineering corpus only; no statistical superiority claim. Manual fields unfilled."}
    (output / "plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
    rows = []
    with analysis_lock(settings.path("data")):
        runtime = (SavedDraftRuntime(replay_dir) if replay_dir else LlamaRuntime(settings)) if any(m in modes for m in ("A", "B", "D")) else None
        try:
            for scenario in scenarios:
                content = (settings.root / scenario["input"]).read_bytes()
                if hashlib.sha256(content).hexdigest() != scenario["sha256"]:
                    raise ValueError("Хеш сценария не совпал с зафиксированным эталоном")
                preparation_started = time.perf_counter()
                imported = import_bytes(content, scenario["input"], settings.limits)
                cases = build_cases(imported.events, settings.limits, settings.correlation.enabled)
                if imported.issues or len(cases) != 1:
                    raise ValueError("Сценарий должен давать ровно один случай без ошибок импорта")
                case = cases[0]
                case.preparation_seconds = time.perf_counter() - preparation_started
                for repeat in range(repeats if any(m in modes for m in "ABD") else 1):
                    paired = None
                    for mode in [m for m in "ABCD" if m in modes or (m == "B" and "D" in modes)]:
                        if mode == "C" and repeat > 0: continue
                        print(f"{scenario['scenario_id']} {mode} repeat {repeat + 1}", flush=True)
                        if isinstance(runtime, SavedDraftRuntime): runtime.select(scenario["scenario_id"], mode)
                        if mode == "D" and paired is None:
                            # If B failed, D cannot generate an unrelated replacement draft.
                            report = b_report.model_copy(deep=True)
                            report.run_id, report.mode, report.status = "run-" + uuid.uuid4().hex, "D", "technical_error"
                            report.attempts = []
                            report.errors.append({"code": "paired_draft_unavailable", "message": "Черновик B недоступен; новая генерация D не выполнялась"})
                            report.measurement.update({"draft_reused": False, "origin_run_id": b_report.run_id, "no_second_generation": True})
                            Store(settings.path("data")).save_report(report)
                        else:
                            report = _analyze_locked(case, mode, settings, runtime if mode != "C" else None, lambda *args: None, True,
                                                     reuse_bundle=paired if mode == "D" else None)
                        if mode == "B":
                            b_report = report
                            if report.draft_ref: paired = load_bundle(Path(report.draft_ref))
                        if mode not in modes: continue
                        (output / (report.run_id + ".json")).write_text(report.model_dump_json(indent=2), encoding="utf-8")
                        # Bundle stores raw records once, reports point to its id.
                        if report.draft_ref:
                            import shutil
                            drafts = output / "drafts"; drafts.mkdir(exist_ok=True)
                            target = drafts / Path(report.draft_ref).name
                            if not target.exists(): shutil.copyfile(report.draft_ref, target)
                        row = evaluate(report, case, scenario)
                        row["repeat"] = repeat + 1
                        rows.append(row)
                        (output / "individual.json").write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
                        if any(error["code"] == "cancelled" for error in report.errors): raise KeyboardInterrupt()
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
