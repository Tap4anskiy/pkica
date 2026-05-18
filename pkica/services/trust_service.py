from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import hashes

from pkica.config import INTERMEDIATE_CERT_PATH, ROOT_CERT_PATH, TRUST_EXPORT_DIR, ensure_ca_directories
from pkica.pki.ca import load_certificate
from pkica.pki.inspect import get_basic_constraints_text, get_cn, get_key_usage_text
from pkica.storage.export import copy_file, write_chain

TRUST_DOWNLOADS = {
    "root.crt.pem": ROOT_CERT_PATH,
    "intermediate.crt.pem": INTERMEDIATE_CERT_PATH,
}


def format_fingerprint(raw: bytes) -> str:
    return ":".join(f"{byte:02X}" for byte in raw)


def file_sha256(path: Path) -> str:
    return format_fingerprint(hashlib.sha256(path.read_bytes()).digest())


def certificate_artifact(role: str, label: str, path: Path, download_name: str) -> dict:
    artifact = {
        "role": role,
        "label": label,
        "path": str(path),
        "download_name": download_name,
        "download_url": f"/trust/download/{download_name}",
        "exists": path.exists(),
    }
    if not path.exists():
        return artifact

    cert = load_certificate(path)
    return {
        **artifact,
        "name": get_cn(cert.subject) or cert.subject.rfc4514_string(),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": f"{cert.serial_number:x}",
        "not_valid_before": cert.not_valid_before_utc.isoformat(),
        "not_valid_after": cert.not_valid_after_utc.isoformat(),
        "fingerprint_sha256": format_fingerprint(cert.fingerprint(hashes.SHA256())),
        "file_sha256": file_sha256(path),
        "basic_constraints": get_basic_constraints_text(cert),
        "key_usage": get_key_usage_text(cert),
    }


def trust_chain_bytes() -> bytes:
    for path in [INTERMEDIATE_CERT_PATH, ROOT_CERT_PATH]:
        if not path.exists():
            raise FileNotFoundError(f"Certificate file not found: {path}")
    return INTERMEDIATE_CERT_PATH.read_bytes() + ROOT_CERT_PATH.read_bytes()


def trust_chain_artifact() -> dict:
    exists = INTERMEDIATE_CERT_PATH.exists() and ROOT_CERT_PATH.exists()
    artifact = {
        "role": "bundle",
        "label": "CA chain",
        "path": "generated from current CA certificates",
        "download_name": "ca-chain.pem",
        "download_url": "/trust/download/ca-chain.pem",
        "exists": exists,
    }
    if not exists:
        return artifact

    data = trust_chain_bytes()
    return {
        **artifact,
        "fingerprint_sha256": format_fingerprint(hashlib.sha256(data).digest()),
        "size": len(data),
    }


def trust_center_status(expiring_days: int = 90) -> dict:
    root = certificate_artifact("root", "Root CA", ROOT_CERT_PATH, "root.crt.pem")
    intermediate = certificate_artifact(
        "intermediate",
        "Intermediate CA",
        INTERMEDIATE_CERT_PATH,
        "intermediate.crt.pem",
    )
    chain = trust_chain_artifact()
    artifacts = [root, intermediate]
    warnings: list[str] = []

    for artifact in artifacts:
        if not artifact["exists"]:
            warnings.append(f"{artifact['label']} certificate is missing: {artifact['path']}")
            continue
        expires_at = datetime.fromisoformat(artifact["not_valid_after"])
        if expires_at <= datetime.now(timezone.utc):
            warnings.append(f"{artifact['label']} certificate has expired.")
        elif expires_at <= datetime.now(timezone.utc) + timedelta(days=expiring_days):
            warnings.append(f"{artifact['label']} certificate expires soon.")

    if root["exists"] and root.get("subject") != root.get("issuer"):
        warnings.append("Root CA certificate is not self-issued.")
    if root["exists"] and intermediate["exists"] and intermediate.get("issuer") != root.get("subject"):
        warnings.append("Intermediate CA issuer does not match Root CA subject.")

    return {
        "ready": root["exists"] and intermediate["exists"],
        "artifacts": artifacts,
        "chain": chain,
        "warnings": warnings,
    }


def export_trust_bundle() -> dict:
    ensure_ca_directories()
    root_out = TRUST_EXPORT_DIR / "root.crt.pem"
    intermediate_out = TRUST_EXPORT_DIR / "intermediate.crt.pem"
    chain_out = TRUST_EXPORT_DIR / "ca-chain.pem"

    copy_file(ROOT_CERT_PATH, root_out)
    copy_file(INTERMEDIATE_CERT_PATH, intermediate_out)
    write_chain([INTERMEDIATE_CERT_PATH, ROOT_CERT_PATH], chain_out)

    return {
        "output_dir": str(TRUST_EXPORT_DIR),
        "root": {
            **certificate_artifact("root", "Root CA", ROOT_CERT_PATH, "root.crt.pem"),
            "export_path": str(root_out),
        },
        "intermediate": {
            **certificate_artifact(
                "intermediate",
                "Intermediate CA",
                INTERMEDIATE_CERT_PATH,
                "intermediate.crt.pem",
            ),
            "export_path": str(intermediate_out),
        },
        "chain": {
            **trust_chain_artifact(),
            "export_path": str(chain_out),
        },
    }
