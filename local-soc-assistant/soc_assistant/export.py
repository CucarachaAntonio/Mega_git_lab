from __future__ import annotations
import html
import json
from pathlib import Path
from .schemas import Case, Report

PRIORITIES = {"high": "высокий", "medium": "средний", "low": "низкий", "unknown": "не определён"}

def render_html(report: Report, case: Case | None = None) -> str:
    esc = lambda value: html.escape(str(value), quote=True)
    parts = ['<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width">',
             '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">',
             '<title>Локальный отчёт ИБ</title><style>body{max-width:1100px;margin:2rem auto;padding:1rem;font:16px system-ui;line-height:1.5;background:#f6f8fc;color:#17243b}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:white;padding:1rem;border:1px solid #dde4ef}a{color:#1257a6}h2{margin-top:2rem}.badge{background:#e1eafa;padding:.3rem .6rem}</style>',
             '<h1>Отчёт анализа событий ИБ</h1>',
             f'<p>{esc(report.case_id)} · режим {esc(report.mode)} · {esc(report.status)}</p>',
             f'<p class="badge">Приоритет: {esc(PRIORITIES[report.priority])}</p>']
    def block(title, value):
        parts.extend([f'<h2>{esc(title)}</h2>', '<pre>' + esc(json.dumps(value, ensure_ascii=False, indent=2)) + '</pre>'])
    block("Основания приоритета", report.priority_reasons)
    parts.append('<h2>Факты и доказательства</h2><ul>')
    for fact in report.facts:
        parts.append(f'<li><a href="#event-{esc(fact.event_id)}">{esc(fact.event_id)}</a> · {esc(fact.field)} = {esc(fact.value)}</li>')
    parts.append('</ul>')
    parts.append('<h2>Ссылки заключений на доказательства</h2>')
    for finding in report.techniques:
        parts.append(f'<h3>{esc(finding.technique_id)} · {esc(finding.verdict)}</h3><p>{esc(finding.rationale)}</p><ul>')
        for ref in finding.evidence:
            parts.append(f'<li><a href="#event-{esc(ref.event_id)}">{esc(ref.event_id)}</a> · {esc(ref.field)} = {esc(ref.value)}</li>')
        for identifier in finding.source_ids:
            parts.append(f'<li><a href="#source-{esc(identifier)}">Фрагмент {esc(identifier)}</a></li>')
        parts.append('</ul>')
    for title, value in [("Временная линия", report.timeline), ("Основания связи", [v.model_dump() for v in report.links]),
                         ("Гипотезы — требуют аналитика", report.hypotheses), ("ATT&CK", [v.model_dump() for v in report.techniques]),
                         ("Рекомендации", [v.model_dump() for v in report.recommendations]), ("Недостающие сведения", report.missing),
                         ("Проверки", [v.model_dump() for v in report.checks]), ("Отказы", report.refusals),
                         ("Технические ошибки", report.errors), ("Ограничения", report.limitations),
                         ("Длительность, секунды", report.durations), ("Версии", report.versions), ("Среда", report.environment)]:
        block(title, value)
    parts.append('<h2>Источники</h2>')
    for source in report.sources:
        parts.append(f'<section id="source-{esc(source.chunk_id)}"><h3>{esc(source.title)}</h3><p>{esc(source.source)} · {esc(source.version)} · {esc(source.chunk_id)}</p><pre>{esc(source.text)}</pre></section>')
    if case:
        parts.append('<h2>События</h2>')
        for event in case.events:
            parts.append(f'<section id="event-{esc(event.event_id)}"><h3>{esc(event.event_id)}</h3><pre>{esc(json.dumps(event.model_dump(), ensure_ascii=False, indent=2))}</pre></section>')
    license_text = report.versions.get("knowledge_license")
    license_file = Path(__file__).resolve().parents[1] / "docs/licenses/MITRE-ATTACK.txt"
    if not license_text and license_file.is_file():
        license_text = license_file.read_text(encoding="utf-8")
    if license_text:
        parts.extend(['<h2>Лицензия и атрибуция MITRE ATT&CK</h2>', '<pre>' + esc(license_text) + '</pre>'])
    parts.append('</html>')
    return "\n".join(parts)
