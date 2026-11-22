"""Reproduce the mechanical release validation, through the normal CLI.
No model downloads or external requests. All test data is synthetic.
Usage: python scripts/validate_upgrade.py --out data/current-validation
"""
from pathlib import Path
import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import zipfile
import uuid

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=Path("data/current-validation"))
    args = parser.parse_args()
    target = args.out.resolve(); target.mkdir(parents=True, exist_ok=True)
    work = ROOT / "data/upgrade-validation-work" / uuid.uuid4().hex
    work.mkdir(parents=True, exist_ok=True)
    commands = []
    child_env = os.environ.copy()
    # This protocol explicitly validates saved drafts; real integration is a separate run.
    child_env.pop("SOC_REAL_LLM", None)
    def run(name, arguments, expected=0):
        started = time.perf_counter()
        result = subprocess.run([sys.executable, *arguments], cwd=ROOT, capture_output=True, text=True,
                                encoding="utf-8", env=child_env, timeout=180)
        (target / (name + ".stdout.txt")).write_text(result.stdout, encoding="utf-8")
        (target / (name + ".stderr.txt")).write_text(result.stderr, encoding="utf-8")
        commands.append({"name": name, "command": ["python", *arguments], "returncode": result.returncode,
                         "expected_returncode": expected, "seconds": time.perf_counter() - started})
        (target / "commands.json").write_text(json.dumps(commands, ensure_ascii=False, indent=2), encoding="utf-8")
        if result.returncode != expected:
            raise RuntimeError(f"{name}: return code {result.returncode}, see saved stdout/stderr")
        print(f"{name}: code {result.returncode}", flush=True)
        return result
    run("pip-check", ["-m", "pip", "check"])
    tests = run("tests", ["-m", "pytest", "-q"])
    run("schemas", ["-m", "soc_assistant.cli", "schemas"])
    run("prepare-index", ["-m", "soc_assistant.cli", "prepare", "--index"])
    ready = run("readiness", ["-m", "soc_assistant.cli", "ready"])
    readiness = json.loads(ready.stdout)
    run("demo-C", ["-m", "soc_assistant.cli", "demo", "--mode", "C", "--out", str(work / "demo-C")])
    run("verify-saved", ["-m", "soc_assistant.cli", "verify", "--bundle", str(work / "demo-C/draft.bundle.json"), "--out", str(work / "verified")])
    if not readiness["generative_ready"]:
        run("model-unavailable", ["-m", "soc_assistant.cli", "demo", "--mode", "D", "--out", str(work / "model-unavailable")], expected=2)
    run("C-original-corpus", ["-m", "soc_assistant.cli", "experiment", "--modes", "C", "--split", "all", "--out", str(work / "C-original")])
    run("controls-four-modes", ["-m", "soc_assistant.cli", "experiment", "--modes", "A", "B", "C", "D", "--repeats", "3", "--split", "all", "--gold", "evaluation/controls.json", "--replay-dir", "examples/drafts", "--out", str(work / "controls")])
    controls = work / "controls"
    rows = json.loads((controls / "individual.json").read_text(encoding="utf-8"))
    summary = json.loads((controls / "summary.json").read_text(encoding="utf-8"))
    gold = json.loads((ROOT / "evaluation/controls.json").read_text(encoding="utf-8"))["scenarios"]
    for row in rows:
        if row["mode"] != "D": continue
        b = next(r for r in rows if r["mode"] == "B" and r["scenario_id"] == row["scenario_id"] and r["repeat"] == row["repeat"])
        assert row["draft_id"] == b["draft_id"] and row["draft_reused"]
        report = json.loads((controls / (row["run_id"] + ".json")).read_text(encoding="utf-8"))
        expected = next(s["expected_verifier_codes_for_saved_draft"] for s in gold if s["scenario_id"] == row["scenario_id"])
        codes = {c["code"] for c in report["checks"] if c["status"] == "failed"}
        assert set(expected) <= codes, (row["scenario_id"], expected, codes)
    assert len(rows) == 100
    fixture_calls = max(json.loads((controls / (r["run_id"] + ".json")).read_text(encoding="utf-8"))["versions"].get("runtime", {}).get("calls", 0) for r in rows)
    assert fixture_calls == 60
    for prefix, folder in (("controls", controls), ("C-original", work / "C-original")):
        for name in ("plan.json", "summary.json", "individual.json", "analyst-review.csv"):
            shutil.copyfile(folder / name, target / (prefix + "-" + name))
    unavailable = None
    if not readiness["generative_ready"]:
        unavailable_report = json.loads((work / "model-unavailable/report.json").read_text(encoding="utf-8"))
        assert unavailable_report["observations"] and unavailable_report["priority"] == "medium"
        unavailable = {"status": unavailable_report["status"], "errors": unavailable_report["errors"],
                       "observations": len(unavailable_report["observations"]), "priority": unavailable_report["priority"]}
    with zipfile.ZipFile(target / "artifacts.zip", "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for folder in ("demo-C", "verified", "model-unavailable", "C-original", "controls"):
            for path in sorted((work / folder).rglob("*")):
                if path.is_file(): archive.write(path, path.relative_to(work).as_posix())
    counts = re.search(r"(\d+) passed, (\d+) skipped", tests.stdout)
    result = {"application": "0.2.0", "schema": "1.2", "validation_date": "2026-11-22", "python": platform.python_version(), "platform": platform.platform(),
        "packages": {p: importlib.metadata.version(p) for p in ("pydantic", "streamlit", "psutil", "pytest")},
        "tests": {"passed": int(counts[1]) if counts else None, "skipped_real_model_integration": int(counts[2]) if counts else None},
        "controls": {"scenarios": 10, "reports": len(rows), "B_D_pairs_same_draft": 30, "expected_code_checks_passed": True,
                     "generations_from_saved_fixtures": fixture_calls, "real_llm": False, "generation_quality_evaluated": False,
                     "technical_errors": sum(r["technical_error"] for r in rows)},
        "original_C": json.loads((work / "C-original/summary.json").read_text(encoding="utf-8")),
        "model_unavailable": unavailable, "windows_executed": False, "new_real_llm_run": False,
        "warning": "Synthetic developer controls and saved Draft fixtures only. No statistical or LLM-quality claim.",
        "source_sha256": {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((ROOT / "soc_assistant").glob("*.py"))}}
    (target / "results.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    checksums = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(target.iterdir()) if p.is_file() and p.name != "SHA256SUMS.json"}
    (target / "SHA256SUMS.json").write_text(json.dumps(checksums, indent=2), encoding="utf-8")
    print(json.dumps({"tests": result["tests"], "controls": result["controls"], "output": str(target)}, ensure_ascii=False, indent=2))

if __name__ == "__main__": main()
