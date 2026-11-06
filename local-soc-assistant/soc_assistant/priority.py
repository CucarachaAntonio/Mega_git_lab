from __future__ import annotations
import json
import re
from .config import Settings
from .schemas import Case
from .profiles import candidates

def prioritize(case: Case, config: Settings):
    assets = json.loads(config.path("assets").read_text(encoding="utf-8")) if config.path("assets").exists() else {}
    recognized = list(candidates(case.events))
    commands = " ".join(c for e in case.events for c in e.entities.get("command", []))
    encoded = bool(re.search(r"(?:^|\s)-(?:enc|encodedcommand)\b", commands, re.I))
    task_create = any(p.technique_id == "T1053.005" for p, _, _ in recognized)
    indicator = bool(recognized) and (encoded or task_create)
    reasons = []
    host_ids = {str(e.fields.get("agent.id")) for e in case.events}
    known_assets = [assets[h] for h in host_ids if h in assets]
    critical = any(a.get("criticality") in config.priority.get("critical_assets", ["critical"]) for a in known_assets)
    if len(known_assets) < len(host_ids):
        reasons.append("Критичность части ресурсов неизвестна; она не предполагается")
    if indicator:
        reasons.append("Подтверждён процесс с проверяемым признаком: encodedcommand или schtasks /create; это повод для проверки")
        if (critical and config.priority.get("high_on_critical_asset_and_indicator", True)) or (encoded and config.priority.get("high_on_encoded_command", False)):
            return "high", reasons + ["Сработало настроенное условие высокого приоритета"]
        return "medium", reasons
    if recognized:
        return "low", reasons + ["Наблюдается запуск оболочки без предусмотренных политикой повышающих признаков; легитимность не установлена"]
    return "unknown", reasons + ["Недостаточно поддерживаемых признаков для определения очередности проверки"]
