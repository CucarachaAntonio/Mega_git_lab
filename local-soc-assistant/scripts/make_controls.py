"""Fixed development controls and saved drafts; never a generation-quality benchmark.
Run from the application root: python scripts/make_controls.py
No verifier/profile imports; expectations are specified explicitly below.
"""
from pathlib import Path
from copy import deepcopy
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
FIELDS = ["data.win.eventdata.image", "data.win.eventdata.commandLine", "data.win.system.eventID", "data.win.system.providerName"]

def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

def event_id(row):
    return "ev-" + hashlib.sha256(json.dumps(row, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()).hexdigest()[:24]

def get(row, field):
    value = row
    for part in field.split("."):
        if not isinstance(value, dict) or part not in value: return None
        value = value[part]
    return value

def main():
    base = {"id": "synthetic-upgrade-001", "timestamp": "2026-11-01T10:00:00+03:00",
        "agent": {"id": "001", "name": "synthetic-control-host"},
        "rule": {"id": "synthetic-100001", "level": 5, "description": "Synthetic process record", "mitre": {"id": ["T1059.001"]}},
        "data": {"win": {"system": {"eventID": "1", "providerName": "Microsoft-Windows-Sysmon"},
            "eventdata": {"image": "C:\\Windows\\System32\\powershell.exe", "commandLine": "powershell.exe Get-Date", "user": "LAB\\analyst"}}}}
    encoded = deepcopy(base); encoded["data"]["win"]["eventdata"]["commandLine"] = "powershell.exe -EncodedCommand RwBlAHQALQBEAGEAdABlAA=="
    missing = deepcopy(base); missing["data"]["win"]["eventdata"].pop("commandLine")
    conflict = deepcopy(base); conflict["data"]["win"]["eventdata"]["commandLine"] = "cmd.exe /c whoami"
    clock = deepcopy(base)
    clock["data"]["win"]["system"]["systemTime"] = "2026-11-01T07:00:00Z"
    clock["data"]["win"]["eventdata"]["utcTime"] = "2026-11-02T07:00:00Z"
    flow = {"event_type": "alert", "timestamp": "2026-11-01T07:00:00Z", "sensor_name": "synthetic-sensor", "flow_id": 42,
            "src_ip": "192.0.2.10", "dest_ip": "192.0.2.20", "alert": {"signature": "Synthetic local control", "severity": 3}}
    flow2 = {**flow, "event_type": "flow", "timestamp": "2026-11-01T07:00:10Z"}
    # All variants of the base process stay in the SAME developer split.
    specs = [
        ("control_legitimate", [base], ["T1059.001"], "low", "legitimate", []),
        ("control_encoded", [encoded], ["T1059.001"], "medium", "sufficient", []),
        ("control_missing_command", [missing], [], "unknown", "insufficient", ["insufficient_evidence"]),
        ("control_field_conflict", [conflict], [], "unknown", "contradiction", ["contradiction"]),
        ("control_time_conflict", [clock], ["T1059.001"], "low", "time_conflict", ["timeline_reproducible"]),
        ("control_bad_fact", [base], ["T1059.001"], "low", "bad_reference", ["invalid_event"]),
        ("control_bad_value", [base], ["T1059.001"], "low", "bad_value", ["content_mismatch"]),
        ("control_bad_source", [base], ["T1059.001"], "low", "bad_source", ["invalid_source"]),
        ("control_wrong_technique", [base], ["T1059.001"], "low", "wrong_technique", ["contradiction"]),
        ("control_suricata_flow", [flow, flow2], [], "unknown", "suricata", []),
    ]
    objects = json.loads((ROOT / "knowledge/enterprise-demo.json").read_text())["objects"]
    definition_ids = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern": continue
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack": definition_ids[ref.get("external_id")] = obj["id"] + ":0"
    scenarios = []
    for name, rows, techniques, priority, kind, codes in specs:
        path = ROOT / "examples/controls" / (name + ".jsonl")
        path.parent.mkdir(parents=True, exist_ok=True)
        content = ("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n").encode()
        path.write_bytes(content)
        row = rows[0]
        refs = [{"event_id": event_id(row), "field": f, "value": get(row, f)} for f in FIELDS if get(row, f) is not None]
        facts = deepcopy(refs)
        source_id = definition_ids["T1059.001"]
        tid = "T1053.005" if kind == "wrong_technique" else "T1059.001"
        if tid != "T1059.001": source_id = definition_ids[tid]
        proposed = [{"technique_id": tid, "rationale": "Заранее заданный контрольный черновик; требуется проверка", "evidence": refs, "source_ids": [source_id]}]
        draft = {"facts": facts, "hypotheses": [], "techniques": proposed, "recommendations": [], "missing": [], "abstentions": []}
        if kind == "bad_reference": draft["facts"][0]["event_id"] = "ev-outside-current-case"
        if kind == "bad_value": draft["facts"][0]["value"] = "fabricated.exe"
        if kind == "bad_source": proposed[0]["source_ids"] = ["fragment-outside-current-corpus"]
        if kind == "time_conflict": draft["timeline"] = [{"event_id": event_id(row), "utc_time": "2026-11-01T07:00:00+00:00"}]
        if kind == "suricata":
            draft.update(facts=[{"event_id": event_id(r), "field": "src_ip", "value": r["src_ip"]} for r in rows], techniques=[], abstentions=["Нет процессной телеметрии Sysmon для сопоставления с поддерживаемыми техниками"])
        for mode in ("A", "B"):
            # Deliberately identical: this experiment validates mechanics, not RAG effectiveness.
            write(ROOT / "examples/drafts" / (name + "." + mode + ".json"), draft)
        opportunities = [{"technique_id": t, "expected": "conclude", "required_evidence_fields": FIELDS} for t in techniques]
        if not techniques: opportunities = [{"technique_id": "T1059.001" if kind != "suricata" else None, "expected": "abstain"}]
        if kind == "wrong_technique": opportunities.append({"technique_id": "T1053.005", "expected": "abstain"})
        assertions = [{"record_number": i, "field": f, "value": get(r, f)} for i, r in enumerate(rows, 1) for f in FIELDS if get(r, f) is not None]
        if kind == "suricata": assertions = [{"record_number": i, "field": "src_ip", "value": r["src_ip"]} for i, r in enumerate(rows, 1)]
        scenarios.append({"scenario_id": name, "family": "upgrade_flow" if kind == "suricata" else "upgrade_process",
            "split": "test" if kind == "suricata" else "tune", "kind": kind,
            "input": path.relative_to(ROOT).as_posix(), "sha256": hashlib.sha256(content).hexdigest(),
            "techniques": techniques, "priority": priority, "should_abstain": not bool(techniques),
            "required_evidence_fields": FIELDS, "assertions": assertions, "opportunities": opportunities,
            "expected_verifier_codes_for_saved_draft": codes, "priority_opportunity": True,
            "time_comparable": kind != "time_conflict", "labels_are_for_evaluator_only": True})
    write(ROOT / "evaluation/controls.json", {"version": "controls-2.0", "purpose": "Developer controls, not a blind test or generation-quality dataset",
        "freeze_policy": "Fixed inputs and manual expectations; do not adjust to improve metrics", "scenarios": scenarios})
    write(ROOT / "examples/controls-manifest.json", {"version": "2.0", "origin": "Synthetic, CC0-1.0; no real user telemetry", "count": len(specs),
        "generator": "scripts/make_controls.py", "gold": "evaluation/controls.json", "saved_drafts": "examples/drafts/", "real_llm": False,
        "warning": "A and B fixtures are identical on purpose; results only verify transport, pairing and deterministic checks."})
    print(f"Created {len(specs)} fixed controls and {2 * len(specs)} saved Draft fixtures")

if __name__ == "__main__": main()
