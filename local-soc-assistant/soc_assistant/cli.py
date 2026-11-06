from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from .config import load_settings

def emit(value):
    print(json.dumps(value, ensure_ascii=False, indent=2))

def _main(argv=None):
    parser = argparse.ArgumentParser(description="Локальный исследовательский ассистент ИБ")
    parser.add_argument("--config", default="config.toml")
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare", help="Отдельная подготовка и обновление")
    prepare.add_argument("--index", action="store_true")
    prepare.add_argument("--model", action="store_true")
    prepare.add_argument("--attack", action="store_true")
    ready = commands.add_parser("ready")
    ready.add_argument("--require-llm", action="store_true")
    commands.add_parser("schemas")
    for name in ("import", "analyze", "demo"):
        sub = commands.add_parser(name)
        if name != "demo": sub.add_argument("file", type=Path)
        if name != "import":
            sub.add_argument("--mode", choices=list("ABCD"), default="C")
            sub.add_argument("--case-index", type=int, default=0)
            sub.add_argument("--out", type=Path)
    exp = commands.add_parser("experiment")
    exp.add_argument("--modes", nargs="+", choices=list("ABCD"), default=list("ABCD"))
    exp.add_argument("--repeats", type=int, default=3)
    exp.add_argument("--split", choices=["tune", "test", "all"], default="test")
    exp.add_argument("--limit", type=int)
    exp.add_argument("--scenarios", nargs="+")
    exp.add_argument("--out", type=Path, default=Path("data/experiment"))
    args = parser.parse_args(argv)
    settings = load_settings(args.config)
    if args.command == "prepare":
        from .prepare import prepare_attack, prepare_index, prepare_model
        if not any((args.index, args.model, args.attack)): parser.error("Укажите --index, --model или --attack")
        if args.model: emit(prepare_model(settings))
        if args.attack: emit(prepare_attack(settings))
        if args.index: emit(prepare_index(settings))
        return 0
    from .security import offline_guard
    offline_guard()
    if args.command == "schemas":
        from .schemas import Draft, Report
        target = settings.root / "schemas"; target.mkdir(exist_ok=True)
        for cls in (Draft, Report):
            from .schemas import SCHEMA_VERSION
            schema = cls.model_json_schema()
            schema["$id"] = f"urn:local-soc-assistant:{cls.__name__.lower()}:{SCHEMA_VERSION}"
            (target / (cls.__name__.lower() + ".schema.json")).write_text(json.dumps(schema, ensure_ascii=False, indent=2), encoding="utf-8")
        emit({"written": str(target)})
        return 0
    if args.command == "ready":
        from .service import readiness
        result = readiness(settings)
        emit(result)
        return 0 if result["generative_ready" if args.require_llm else "mode_C_ready"] else 2
    if args.command == "experiment":
        from .evaluation import experiment
        emit(experiment(settings, args.modes, args.repeats, args.split, args.out, args.limit, args.scenarios))
        return 0
    from .ingest import import_bytes
    from .correlate import build_cases
    from .storage import Store
    path = settings.root / "examples/demo.jsonl" if args.command == "demo" else args.file
    if not path.is_file(): parser.error("Входной файл отсутствует")
    # Read at most the configured file limit plus one byte.
    with path.open("rb") as stream:
        content = stream.read(settings.limits.upload_mb * 1024 * 1024 + 1)
    result = import_bytes(content, path.name, settings.limits)
    store = Store(settings.path("data"))
    if len(content) <= settings.limits.upload_mb * 1024 * 1024:
        store.save_import(content, path.name, result)
    cases = build_cases(result.events, settings.limits, settings.correlation.enabled)
    for case in cases: store.save_case(case)
    if args.command == "import":
        emit({"accepted": len(result.events), "rejected": result.rejected_records, "file_errors": result.file_errors, "duplicates": result.duplicate_records,
              "issues": [i.model_dump() for i in result.issues], "cases": [c.case_id for c in cases]})
        return 0 if not result.issues else 3
    if not cases or args.case_index < 0 or args.case_index >= len(cases):
        emit({"error": "Нет выбранного случая", "issues": [i.model_dump() for i in result.issues]})
        return 3
    from .service import analyze
    from .export import render_html
    report = analyze(cases[args.case_index], args.mode, settings, progress=lambda label, value: print(f"[{value}%] {label}", file=sys.stderr, flush=True))
    output = args.out or settings.path("data") / "exports" / report.run_id
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(report.model_dump_json(indent=2), encoding="utf-8")
    (output / "report.html").write_text(render_html(report, cases[args.case_index]), encoding="utf-8")
    emit({"status": report.status, "run_id": report.run_id, "priority": report.priority,
          "techniques": [f.technique_id for f in report.techniques if f.verdict != "rejected"],
          "errors": report.errors, "import_accepted": len(result.events), "import_rejected": result.rejected_records, "import_file_errors": result.file_errors,
          "json": str(output / "report.json"), "html": str(output / "report.html")})
    return 2 if report.status == "technical_error" else 0

def main(argv=None):
    from .security import BusyError
    try:
        return _main(argv)
    except KeyboardInterrupt:
        emit({"status": "cancelled", "message": "Эксперимент прерван; завершённые и частичные результаты сохранены"})
        return 130
    except BusyError as exc:
        emit({"status": "busy", "message": str(exc)})
        return 4
    except (OSError, ValueError) as exc:
        emit({"status": "error", "error_type": type(exc).__name__, "message": "Проверьте пути, конфигурацию и готовность по README"})
        return 2

if __name__ == "__main__":
    sys.exit(main())
