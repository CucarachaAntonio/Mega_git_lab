from __future__ import annotations
import hashlib
import json
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from contextlib import contextmanager
from .schemas import Case, ImportResult, Report

class Store:
    def __init__(self, directory: Path):
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=True)
        self.path = directory / "history.sqlite"
        with self.connect() as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS imports(hash TEXT PRIMARY KEY, filename TEXT, result TEXT);
            CREATE TABLE IF NOT EXISTS cases(id TEXT PRIMARY KEY, body TEXT);
            CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY, case_id TEXT, mode TEXT, created TEXT, body TEXT);
            ''')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=20)
        try:
            db.execute("PRAGMA journal_mode=WAL")
            with db:
                yield db
        finally:
            db.close()

    def save_import(self, content: bytes, filename: str, result: ImportResult):
        digest = hashlib.sha256(content).hexdigest()
        folder = self.directory / "originals"
        folder.mkdir(exist_ok=True)
        (folder / (digest + ".jsonl")).write_bytes(content)
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO imports VALUES(?,?,?)", (digest, Path(filename).name, result.model_dump_json()))

    def save_case(self, case: Case):
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO cases VALUES(?,?)", (case.case_id, case.model_dump_json()))

    def cases(self) -> list[Case]:
        with self.connect() as db:
            return [Case.model_validate_json(r[0]) for r in db.execute("SELECT body FROM cases ORDER BY id")]

    def save_report(self, report: Report):
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO runs VALUES(?,?,?,?,?)", (report.run_id, report.case_id, report.mode,
                       datetime.now(timezone.utc).isoformat(), report.model_dump_json()))

    def reports(self, case_id: str | None = None) -> list[Report]:
        with self.connect() as db:
            rows = db.execute("SELECT body FROM runs WHERE case_id=? ORDER BY created DESC", (case_id,)) if case_id else db.execute("SELECT body FROM runs ORDER BY created DESC")
            return [Report.model_validate_json(row[0]) for row in rows]

    def imports(self):
        with self.connect() as db:
            return [{"sha256": row[0], "filename": row[1], "result": json.loads(row[2])} for row in db.execute("SELECT * FROM imports")]
