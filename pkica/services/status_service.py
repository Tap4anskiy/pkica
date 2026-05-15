from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from pkica.config import CRL_PATH, INTERMEDIATE_CERT_PATH, INTERMEDIATE_KEY_PATH, ISSUED_DB_PATH, REQUESTS_DB_PATH, REVOKED_DB_PATH, ROOT_CERT_PATH, ROOT_KEY_PATH
from pkica.pki.ca import load_certificate
from pkica.storage.status import count_by_status, load_json_list


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

    return {
        "root_ready": ROOT_CERT_PATH.exists(),
        "root_key_present": ROOT_KEY_PATH.exists(),
        "intermediate_ready": INTERMEDIATE_KEY_PATH.exists() and INTERMEDIATE_CERT_PATH.exists(),
        "crl_ready": CRL_PATH.exists(),
        "requests_total": len(requests),
        "request_stats": count_by_status(requests),
        "certificates_total": len(issued),
        "certificate_stats": count_by_status(issued),
        "revocations_total": len(revoked),
        "paths": {
            "root_cert": str(ROOT_CERT_PATH) if ROOT_CERT_PATH.exists() else "-",
            "intermediate_cert": str(INTERMEDIATE_CERT_PATH) if INTERMEDIATE_CERT_PATH.exists() else "-",
            "crl": str(CRL_PATH) if CRL_PATH.exists() else "-",
        },
        "warnings": warnings,
    }

