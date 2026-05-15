from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID

from pkica.config import CRL_PATH, INTERMEDIATE_CERT_PATH, INTERMEDIATE_KEY_PATH, ISSUED_DB_PATH, REQUESTS_DB_PATH, REVOKED_DB_PATH, ROOT_CERT_PATH, ROOT_KEY_PATH
from pkica.pki.ca import load_certificate
from pkica.storage.status import count_by_status, load_json_list


def safe_exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError:
        return False


def cert_common_name(cert: x509.Certificate) -> str:
    attributes = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if attributes:
        return attributes[0].value
    return cert.subject.rfc4514_string()


def cert_info(path: Path) -> dict | None:
    if not safe_exists(path):
        return None
    cert = load_certificate(path)
    return {
        "name": cert_common_name(cert),
        "subject": cert.subject.rfc4514_string(),
        "not_valid_after": cert.not_valid_after_utc.isoformat(),
    }


def get_status(expiring_days: int = 30) -> dict:
    requests = load_json_list(REQUESTS_DB_PATH)
    issued = load_json_list(ISSUED_DB_PATH)
    revoked = load_json_list(REVOKED_DB_PATH)
    now = datetime.now(timezone.utc)
    soon = now + timedelta(days=expiring_days)
    warnings = []
    for record in issued:
        try:
            not_after = datetime.fromisoformat(record["not_valid_after"])
        except Exception:
            continue
        if record.get("status") != "revoked" and now <= not_after <= soon:
            expires_at = not_after.astimezone(timezone.utc).strftime("%d.%m.%Y %H:%M UTC")
            warnings.append(f"Certificate {record.get('serial_number')} expires at {expires_at}")

    root_cert_info = cert_info(ROOT_CERT_PATH)
    intermediate_cert_info = cert_info(INTERMEDIATE_CERT_PATH)

    return {
        "root_ready": safe_exists(ROOT_CERT_PATH),
        "root_cert": root_cert_info,
        "root_key_present": safe_exists(ROOT_KEY_PATH),
        "intermediate_ready": safe_exists(INTERMEDIATE_CERT_PATH),
        "intermediate_key_present": safe_exists(INTERMEDIATE_KEY_PATH),
        "intermediate_cert": intermediate_cert_info,
        "crl_ready": safe_exists(CRL_PATH),
        "requests_total": len(requests),
        "request_stats": count_by_status(requests),
        "certificates_total": len(issued),
        "certificate_stats": count_by_status(issued),
        "revocations_total": len(revoked),
        "paths": {
            "root_cert": str(ROOT_CERT_PATH) if safe_exists(ROOT_CERT_PATH) else "-",
            "intermediate_cert": str(INTERMEDIATE_CERT_PATH) if safe_exists(INTERMEDIATE_CERT_PATH) else "-",
            "crl": str(CRL_PATH) if safe_exists(CRL_PATH) else "-",
        },
        "warnings": warnings,
    }
