"""Raw-record addressing and typed equality, shared as data primitives, never an LLM judge."""
from __future__ import annotations
import hashlib
import json

MISSING = object()

def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()

def pointer(parts):
    return "/" + "/".join(str(p).replace("~", "~0").replace("/", "~1") for p in parts)

def resolve(raw, path):
    if path == "": return raw
    if not path.startswith("/"): return MISSING
    current = raw
    for part in path[1:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict): current = current.get(part, MISSING)
        elif isinstance(current, list) and part.isdecimal() and int(part) < len(current): current = current[int(part)]
        else: return MISSING
        if current is MISSING: return MISSING
    return current

def typed_equal(left, right):
    return type(left) is type(right) and left == right

def raw_field(event, field):
    origin = event.field_origins.get(field)
    if origin:
        if origin.kind != "original" or origin.source_id != event.source_id or origin.record_id != event.record_id:
            return MISSING
        return resolve(event.raw, origin.json_pointer)
    # Version 1.1 cases: derive only unambiguous paths, never fall back to normalized values.
    if field.startswith("/"): return resolve(event.raw, field)
    parts = field.split(".")
    current = event.raw
    for i, key in enumerate(parts):
        if isinstance(current, dict) and ".".join(parts[i:]) in current and len(parts[i:]) > 1:
            return MISSING
        if isinstance(current, dict): current = current.get(key, MISSING)
        elif isinstance(current, list) and key.isdecimal() and int(key) < len(current): current = current[int(key)]
        else: return MISSING
    return current
