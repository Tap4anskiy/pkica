from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class WebMessage:
    text: str
    level: str = "info"

