from __future__ import annotations
import hashlib
import json
import re
import sqlite3
from pathlib import Path
from contextlib import closing
from .schemas import Case, Chunk

ALGORITHM = "fts5-bm25-title6-definition-quota-v4"

class SearchError(RuntimeError):
    pass

def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()

class Snapshot:
    def __init__(self, path: Path):
        self.path = path
        self.sha256 = file_hash(path)
        body = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(body, dict) or body.get("type") != "bundle" or not isinstance(body.get("objects"), list):
            raise ValueError("Ожидается ATT&CK STIX bundle")
        self.provenance = body.get("x_local_provenance", {})
        manifest_path = path.parent / "manifest.json"
        if not self.provenance and manifest_path.exists():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if manifest.get("attack_original_sha256") == self.sha256:
                self.provenance = {"release": manifest["attack_release"], "source": manifest["attack_original_url"], "scope": "full Enterprise ATT&CK"}
        self.techniques = {}
        self.documents = []
        for obj in body["objects"]:
            if not isinstance(obj, dict):
                raise ValueError("Повреждённый объект STIX")
            if obj.get("type") not in {"attack-pattern", "course-of-action"}:
                continue
            refs = [r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"]
            technique_id = next((r.get("external_id") for r in refs if str(r.get("external_id", "")).startswith("T")), None)
            if technique_id and obj.get("type") == "attack-pattern":
                self.techniques[technique_id] = obj
            if not obj.get("revoked") and not obj.get("x_mitre_deprecated"):
                self.documents.append((obj, technique_id if obj.get("type") == "attack-pattern" else None, refs[0].get("url", "") if refs else ""))

        for obj in body["objects"]:
            if obj.get("type") == "relationship" and obj.get("relationship_type") == "uses" and obj.get("description") and not obj.get("revoked") and not obj.get("x_mitre_deprecated"):
                contextual = dict(obj)
                contextual["name"] = "Исторический пример ATT&CK — только контекст"
                contextual["description"] = "CONTEXT ONLY. Not evidence for the current case. " + obj["description"]
                self.documents.append((contextual, None, "MITRE ATT&CK STIX:" + obj["id"]))

    def active(self, identifier: str):
        obj = self.techniques.get(identifier)
        return bool(obj and not obj.get("revoked") and not obj.get("x_mitre_deprecated"))

def build_index(snapshot_path: Path, index_path: Path, chunk_chars: int = 1800, runbook: Path | None = None):
    snapshot = Snapshot(snapshot_path)
    index_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = index_path.with_suffix(".building.sqlite")
    temporary.unlink(missing_ok=True)
    documents = []
    for obj, technique_id, source in snapshot.documents:
        documents.append((obj["id"], obj.get("name", ""), obj.get("description", ""), source,
                          obj.get("x_mitre_version", obj.get("modified", "unknown")), technique_id, snapshot.sha256))
    if runbook and runbook.exists():
        documents.append(("local-runbook-v1", "Локальная инструкция проверки", runbook.read_text(encoding="utf-8"),
                          "local:knowledge/runbook.md", "1.0", None, file_hash(runbook)))
    with closing(sqlite3.connect(temporary)) as db:
        db.executescript('''
        CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT);
        CREATE TABLE chunks(chunk_id TEXT PRIMARY KEY,document_id TEXT,text TEXT,title TEXT,source TEXT,version TEXT,source_sha256 TEXT,technique_id TEXT);
        CREATE VIRTUAL TABLE search USING fts5(chunk_id UNINDEXED, title, text, tokenize='unicode61');
        ''')
        for doc_id, title, body, source, version, tech, sha in documents:
            for offset in range(0, max(1, len(body)), chunk_chars):
                chunk_id = f"{doc_id}:{offset // chunk_chars}"
                text = body[offset:offset + chunk_chars]
                db.execute("INSERT INTO chunks VALUES(?,?,?,?,?,?,?,?)", (chunk_id, doc_id, text, title, source, version, sha, tech))
                db.execute("INSERT INTO search VALUES(?,?,?)", (chunk_id, title, text))
        metadata = {"sqlite_version": sqlite3.sqlite_version, "snapshot_sha256": snapshot.sha256, "chunk_chars": str(chunk_chars), "algorithm": ALGORITHM,
                    "runbook_sha256": file_hash(runbook) if runbook and runbook.exists() else "none"}
        metadata["index_version"] = hashlib.sha256(json.dumps(metadata, sort_keys=True).encode()).hexdigest()
        db.executemany("INSERT INTO metadata VALUES(?,?)", metadata.items())
        db.commit()
    temporary.replace(index_path)
    return metadata

class Retriever:
    def __init__(self, index_path: Path):
        self.path = index_path
        if not index_path.is_file():
            raise SearchError("Индекс отсутствует; выполните prepare --index")
        try:
            with self.connect() as db:
                self.metadata = dict(db.execute("SELECT key,value FROM metadata"))
        except sqlite3.Error as exc:
            raise SearchError("Индекс повреждён") from exc

    def connect(self):
        return closing(sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True))

    def search(self, query: str, limit=4) -> list[Chunk]:
        tokens = list(dict.fromkeys(re.findall(r"[\w.-]{2,40}", query.lower(), re.UNICODE)))[:24]
        if not tokens:
            return []
        expression = " OR ".join('"' + token.replace('"', '""') + '"' for token in tokens)
        try:
            with self.connect() as db:
                base = "SELECT c.*, bm25(search,0.0,6.0,1.0) AS rank FROM search JOIN chunks c ON c.chunk_id=search.chunk_id WHERE search MATCH ? "
                definitions = db.execute(base + "AND c.technique_id IS NOT NULL ORDER BY rank ASC,c.chunk_id ASC LIMIT ?", (expression, max(100, limit * 24))).fetchall()
                context = db.execute(base + "AND c.technique_id IS NULL ORDER BY rank ASC,c.chunk_id ASC LIMIT ?", (expression, max(100, limit * 24))).fetchall()
                def diverse(rows):
                    chosen, documents = [], set()
                    for row in rows:
                        if row[1] not in documents:
                            chosen.append(row); documents.add(row[1])
                    return chosen
                definitions, context = diverse(definitions), diverse(context)
                quota = max(1, limit - 1)
                rows = definitions[:quota] + context[:limit - min(quota, len(definitions))]
                if len(rows) < limit:
                    rows += definitions[quota:quota + limit - len(rows)]
        except sqlite3.Error as exc:
            raise SearchError("Сбой полнотекстового поиска") from exc
        selected, seen = [], set()
        for row in rows:
            if row[1] in seen:
                continue
            seen.add(row[1])
            selected.append(row)
            if len(selected) >= limit:
                break
        return [Chunk(chunk_id=r[0], document_id=r[1], text=r[2], title=r[3], source=r[4], version=r[5],
                      source_sha256=r[6], technique_id=r[7], score=-r[8]) for r in selected]

def case_query(case: Case) -> str:
    """Only observable normalized input; no dataset labels or Wazuh ATT&CK tags."""
    terms = []
    for event in case.events:
        for process in event.entities.get("process", []):
            executable = process.replace("\\", "/").rsplit("/", 1)[-1]
            terms.extend([executable, executable.rsplit(".", 1)[0]])
        for command in event.entities.get("command", []):
            lower = command.lower()
            for word in ("powershell", "cmd.exe", "schtasks", "scheduled", "create", "encodedcommand", "script"):
                if word in lower:
                    terms.append(word)
    return " ".join(dict.fromkeys(terms))[:600] or "process execution investigation"
