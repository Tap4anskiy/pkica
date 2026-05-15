from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from pkica.config import CRL_PATH, INTERMEDIATE_CERT_PATH, INTERMEDIATE_KEY_PATH, ISSUED_DB_PATH, REQUESTS_DB_PATH, REVOKED_DB_PATH, ROOT_CERT_PATH, ROOT_KEY_PATH
from pkica.pki.ca import load_certificate
from pkica.storage.status import count_by_status, load_json_list


def safe_exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError:
        return False


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
            warnings.append(f"Certificate {record.get('serial_number')} expires at {record.get('not_valid_after')}")

    root_cert_info = None
    if safe_exists(ROOT_CERT_PATH):
        root_cert = load_certificate(ROOT_CERT_PATH)
        root_cert_info = {
            "subject": root_cert.subject.rfc4514_string(),
            "not_valid_after": root_cert.not_valid_after_utc.isoformat(),
        }

    intermediate_cert_info = None
    if safe_exists(INTERMEDIATE_CERT_PATH):
        intermediate_cert = load_certificate(INTERMEDIATE_CERT_PATH)
        intermediate_cert_info = {
            "subject": intermediate_cert.subject.rfc4514_string(),
            "not_valid_after": intermediate_cert.not_valid_after_utc.isoformat(),
        }

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
