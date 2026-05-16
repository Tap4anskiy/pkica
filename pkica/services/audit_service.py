from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from pkica.config import AUDIT_LOG_PATH
from pkica.storage.audit import append_jsonl


def log_event(action: str, result: str = "success", **details: object) -> None:
    append_jsonl(AUDIT_LOG_PATH, {"action": action, "result": result, **details})


def list_events(
    limit: int = 100,
    action: str | None = None,
    source: str | None = None,
    result: str | None = None,
    query: str | None = None,
) -> list[dict]:
    if not AUDIT_LOG_PATH.exists():
        return []

    rows: list[dict] = []
    query_value = query.lower().strip() if query else ""
    for line in AUDIT_LOG_PATH.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            event = {"timestamp": "", "action": "raw", "message": line}
        if action and event.get("action") != action:
            continue
        if source and event.get("source") != source:
            continue
        if result and event.get("result") != result:
            continue
        if query_value and query_value not in json.dumps(event, ensure_ascii=False).lower():
            continue
        rows.append(event)
    return rows[-limit:]


def event_values(events: Iterable[dict], key: str) -> list[str]:
    values = {str(event[key]) for event in events if event.get(key) not in (None, "")}
    return sorted(values)


def read_tail(limit: int = 100) -> list[str]:
    if not AUDIT_LOG_PATH.exists():
        return []
    return AUDIT_LOG_PATH.read_text(encoding="utf-8").splitlines()[-limit:]
