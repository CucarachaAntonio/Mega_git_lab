"""Three intentionally narrow, independently executable evidence profiles."""
from __future__ import annotations
import re
from dataclasses import dataclass
from .schemas import Event, Evidence
from .evidence import MISSING, raw_field

IMAGE = "data.win.eventdata.image"
COMMAND = "data.win.eventdata.commandLine"
EVENT_ID = "data.win.system.eventID"
PROVIDER = "data.win.system.providerName"
PROFILE_VERSION = "process-profiles-1.2-raw"

@dataclass(frozen=True)
class Profile:
    technique_id: str
    executable: str
    command_pattern: str
    additional: tuple[str, ...]
    description: str
    optional_fields: tuple[str, ...] = ("data.win.eventdata.parentImage", "data.win.eventdata.user")

PROFILES = {
 "T1059.001": Profile("T1059.001", "powershell.exe", r"(?:^|[\\\s\"])(?:powershell(?:\.exe)?)(?:[\s\"]|$)", (),
                       "Наблюдается запуск PowerShell; злонамеренность этим не установлена"),
 "T1059.003": Profile("T1059.003", "cmd.exe", r"(?:^|[\\\s\"])(?:cmd(?:\.exe)?)(?:[\s\"]|$)", (),
                       "Наблюдается Windows Command Shell; злонамеренность этим не установлена"),
 "T1053.005": Profile("T1053.005", "schtasks.exe", r"(?:^|[\\\s\"])(?:schtasks(?:\.exe)?)(?:[\s\"]|$)", (r"(?:^|\s)/create(?:\s|$)",),
                       "Наблюдается запуск schtasks /create; успешное создание задачи требует дополнительных событий"),
}

def inspect(profile: Profile, event: Event):
    fields = {key: value for key in event.fields if (value := raw_field(event, key)) is not MISSING}
    missing = []
    contradictions = []
    image = fields.get(IMAGE)
    command = fields.get(COMMAND)
    if type(fields.get(EVENT_ID)) not in (int, str) or fields.get(EVENT_ID) not in (1, "1") or fields.get(PROVIDER) != "Microsoft-Windows-Sysmon":
        missing.append("Sysmon Event ID 1 с providerName=Microsoft-Windows-Sysmon")
    if image is None:
        missing.append(IMAGE)
    elif str(image).replace("\\", "/").rsplit("/", 1)[-1].lower() != profile.executable:
        contradictions.append("Имя запущенного процесса не соответствует профилю")
    if not command:
        missing.append(COMMAND)
    elif not re.search(profile.command_pattern, str(command), re.I):
        contradictions.append("Командная строка не соответствует профилю процесса")
    elif any(not re.search(pattern, str(command), re.I) for pattern in profile.additional):
        missing.append("Обязательный аргумент /create")
    evidence = [Evidence(event_id=event.event_id, field=key, value=fields[key],
                        source_id=event.source_id, record_id=event.record_id,
                        json_pointer=event.field_origins[key].json_pointer if key in event.field_origins else None)
                for key in (IMAGE, COMMAND, EVENT_ID, PROVIDER) if key in fields]
    return missing, contradictions, evidence

def candidates(events: list[Event]):
    for event in events:
        for profile in PROFILES.values():
            missing, contradictions, evidence = inspect(profile, event)
            if not missing and not contradictions:
                yield profile, event, evidence
