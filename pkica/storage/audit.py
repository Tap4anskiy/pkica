from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from pkica.storage.secure import append_private_text


def append_jsonl(path: Path, event: dict) -> None:
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **event,
    }

    append_private_text(path, json.dumps(event, ensure_ascii=False) + "\n")
