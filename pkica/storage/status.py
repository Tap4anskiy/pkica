from __future__ import annotations

import json
from pathlib import Path


def load_json_list(path: Path) -> list[dict]:
    try:
        if not path.exists():
            return []
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []


def count_by_status(records: list[dict]) -> dict[str, int]:
    result: dict[str, int] = {}

    for record in records:
        status = record.get("status", "unknown")
        result[status] = result.get(status, 0) + 1

    return result
