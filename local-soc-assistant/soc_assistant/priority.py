"""Versioned urgency policy. Asset context is enrichment, never a journal fact."""
from __future__ import annotations
import json
import re
from .config import Settings
from .schemas import Case
from .profiles import candidates, COMMAND
from .evidence import digest, raw_field, MISSING

PRIORITY_VERSION = "urgency-policy-2.0"

def priority_context(config: Settings):
    path = config.path("assets")
    assets = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    if not isinstance(assets, dict) or any(not isinstance(v, dict) for v in assets.values()):
        raise ValueError("assets must be a mapping of asset objects")
    context = {"version": PRIORITY_VERSION, "policy": config.priority, "assets": assets,
               "assets_origin": "local:" + config.paths["assets"], "kind": "enrichment"}
    context["sha256"] = digest(context)
    return context

def priority_decision(case: Case, context: dict):
    policy, assets = context.get("policy", {}), context.get("assets", {})
    recognized = list(candidates(case.events))
    # An encoded command only increases urgency on the SAME observed process
    # that passed a profile; unrelated text cannot increase another event's score.
    encoded = any(re.search(r"(?:^|\s)-(?:enc|encodedcommand)\b", str(raw_field(event, COMMAND)), re.I)
                  for _, event, _ in recognized)
    task_create = any(p.technique_id == "T1053.005" for p, _, _ in recognized)
    indicator = encoded or task_create
    reasons, host_ids = [], set()
    bases = []
    for _, event, evidence in recognized:
        bases.extend(ref.model_dump() for ref in evidence)
        host = raw_field(event, "agent.id") if "agent.id" in event.fields else MISSING
        if host is not MISSING: host_ids.add(str(host))
    # Unknown assets are recorded even when no supported process was observed.
    all_hosts = {str(raw_field(e, "agent.id")) for e in case.events if "agent.id" in e.fields and raw_field(e, "agent.id") is not MISSING}
    known = {h: assets[h] for h in all_hosts if h in assets}
    relevant = {h: assets[h] for h in host_ids if h in assets}
    critical = any(a.get("criticality") in policy.get("critical_assets", ["critical"]) for a in relevant.values())
    if len(known) < len(all_hosts): reasons.append("Критичность части ресурсов неизвестна; она не предполагается")
    category = "unknown"
    if indicator:
        reasons.append("Наблюдается процесс с encodedcommand или schtasks /create; требуется проверка")
        category = "high" if ((critical and policy.get("high_on_critical_asset_and_indicator", True)) or (encoded and policy.get("high_on_encoded_command", False))) else "medium"
        if category == "high": reasons.append("Сработало настроенное условие высокого приоритета")
    elif recognized:
        category = "low"
        reasons.append("Наблюдается запуск оболочки без повышающих признаков; легитимность не установлена")
    else: reasons.append("Недостаточно поддерживаемых признаков для определения очередности проверки")
    return {"category": category, "reasons": reasons, "evidence": bases, "asset_ids": sorted(relevant),
            "asset_context": relevant, "policy_version": PRIORITY_VERSION, "context_sha256": context.get("sha256"),
            "urgency_is_confirmation": False}

def prioritize(case: Case, config: Settings):
    decision = priority_decision(case, priority_context(config))
    return decision["category"], decision["reasons"]
