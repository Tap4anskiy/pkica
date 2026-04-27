from __future__ import annotations

import shutil
from pathlib import Path


def copy_file(src: Path, dst: Path) -> None:
    if not src.exists():
        raise FileNotFoundError(f"Source file not found: {src}")

    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def write_chain(cert_paths: list[Path], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    data = b""
    for path in cert_paths:
        if not path.exists():
            raise FileNotFoundError(f"Certificate file not found: {path}")
        data += path.read_bytes()

    output_path.write_bytes(data)