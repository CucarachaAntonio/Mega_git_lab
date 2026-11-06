from __future__ import annotations
import hashlib
import json
from datetime import datetime
from .schemas import Case, Event, Link
from .config import Limits

CORRELATION_VERSION = "bounded-links-provenance-1.1"

def _relation(left: Event, right: Event, enabled):
    host1 = left.fields.get("agent.id")
    host2 = right.fields.get("agent.id")
    if not host1 or str(host1).strip().lower() in {"-", "unknown", "n/a"} or host1 != host2:
        return None
    for entity in ("process", "account"):
        if f"same_host_{entity}_v1" not in enabled:
            continue
        values = sorted(set(left.entities.get(entity, [])) & set(right.entities.get(entity, [])))
        if values:
            return f"same_host_{entity}_v1", [f"agent.id={host1}", f"{entity}={values[0]}"]
    return None

def build_cases(events: list[Event], limits: Limits, enabled=None) -> list[Case]:
    enabled = ["same_host_process_v1", "same_host_account_v1"] if enabled is None else enabled
    unique = {event.event_id: event for event in events}
    ordered = sorted(unique.values(), key=lambda e: (e.utc_time is None, e.utc_time or "", e.event_id))
    groups: list[list[Event]] = []
    all_links: list[list[Link]] = []
    for event in ordered:
        matched = False
        if event.utc_time:
            for index, group in enumerate(groups):
                if not group[0].utc_time or len(group) >= limits.max_case_events:
                    continue
                span = (datetime.fromisoformat(event.utc_time) - datetime.fromisoformat(group[0].utc_time)).total_seconds()
                if not 0 <= span <= limits.window_seconds:
                    continue
                for previous in reversed(group):
                    relation = _relation(previous, event, enabled)
                    if relation:
                        rule, reasons = relation
                        delta = (datetime.fromisoformat(event.utc_time) - datetime.fromisoformat(previous.utc_time)).total_seconds()
                        all_links[index].append(Link(from_event=previous.event_id, to_event=event.event_id,
                                                     rule=rule, reasons=reasons, delta_seconds=delta))
                        group.append(event)
                        matched = True
                        break
                if matched:
                    break
        if not matched:
            groups.append([event]); all_links.append([])
    result = []
    for group, links in zip(groups, all_links):
        identity = sorted((e.event_id, e.file_sha256, e.file_name, e.record_number) for e in group)
        digest = hashlib.sha256(json.dumps(identity, ensure_ascii=False).encode()).hexdigest()[:20]
        warnings = sorted({e.time_warning for e in group if e.time_warning})
        times = [e.utc_time for e in group if e.utc_time]
        if len(times) != len(set(times)):
            warnings.append("Одинаковые временные метки: взаимный порядок этих событий не установлен")
        warnings.append("Связывание означает совместную проверку, причинная связь не установлена")
        result.append(Case(case_id="case-" + digest, events=group, links=links, warnings=warnings))
    return result
