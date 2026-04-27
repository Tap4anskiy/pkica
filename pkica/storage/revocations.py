from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_revocations(db_path: Path) -> list[dict]:
    if not db_path.exists():
        return []

    return json.loads(db_path.read_text(encoding="utf-8"))


def save_revocations(db_path: Path, records: list[dict]) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.write_text(
        json.dumps(records, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def is_revoked(db_path: Path, serial_number: str) -> bool:
    serial_number = serial_number.lower().replace("0x", "")
    records = load_revocations(db_path)

    return any(
        record["serial_number"].lower().replace("0x", "") == serial_number
        for record in records
    )


def add_revocation(
    db_path: Path,
    serial_number: str,
    reason: str,
    cert_path: str,
) -> dict:
    serial_number = serial_number.lower().replace("0x", "")

    records = load_revocations(db_path)

    if any(record["serial_number"] == serial_number for record in records):
        raise ValueError(f"Certificate already revoked: {serial_number}")

    record = {
        "serial_number": serial_number,
        "reason": reason,
        "cert_path": cert_path,
        "revoked_at": now_iso(),
    }

    records.append(record)
    save_revocations(db_path, records)

    return record