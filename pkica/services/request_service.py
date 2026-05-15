from __future__ import annotations

import tempfile
from pathlib import Path

from cryptography import x509

from pkica.config import REQUESTS_DB_PATH, REQUESTS_DIR, ensure_ca_directories
from pkica.pki.csr import load_csr
from pkica.policy.profiles import validate_csr_for_profile
from pkica.storage.requests import find_request, load_requests, submit_request, update_request_status
from pkica.services.audit_service import log_event


ALLOWED_PROFILES = {"server_tls", "client_tls"}


def _validate_profile(profile: str) -> None:
    if profile not in ALLOWED_PROFILES:
        raise ValueError(f"Unsupported certificate profile: {profile}")


def submit_csr_file(csr_path: Path, profile: str, *, source: str = "service") -> dict:
    ensure_ca_directories()
    _validate_profile(profile)
    csr = load_csr(csr_path)
    validate_csr_for_profile(csr, profile)
    record = submit_request(REQUESTS_DB_PATH, csr_path, REQUESTS_DIR, profile)
    log_event("req.submit", request_id=record["id"], profile=profile, source=source)
    return record


def submit_csr_pem(csr_pem: str, profile: str, *, source: str = "web") -> dict:
    ensure_ca_directories()
    _validate_profile(profile)
    with tempfile.NamedTemporaryFile("w", suffix=".csr.pem", delete=False, encoding="utf-8") as handle:
        handle.write(csr_pem)
        temp_path = Path(handle.name)
    try:
        return submit_csr_file(temp_path, profile, source=source)
    finally:
        temp_path.unlink(missing_ok=True)


def list_requests(status: str | None = None) -> list[dict]:
    records = load_requests(REQUESTS_DB_PATH)
    if status:
        records = [record for record in records if record.get("status") == status]
    return records


def get_request(request_id: int) -> dict:
    return find_request(load_requests(REQUESTS_DB_PATH), request_id)


def csr_for_request(record: dict) -> x509.CertificateSigningRequest:
    return load_csr(Path(record["stored_csr_path"]))


def approve_request(request_id: int, *, source: str = "service") -> dict:
    record = update_request_status(REQUESTS_DB_PATH, request_id, "approved")
    log_event("req.approve", request_id=request_id, profile=record.get("profile"), source=source)
    return record


def reject_request(request_id: int, reason: str, *, source: str = "service") -> dict:
    record = update_request_status(REQUESTS_DB_PATH, request_id, "rejected", reason=reason)
    log_event("req.reject", request_id=request_id, profile=record.get("profile"), reason=reason, source=source)
    return record


def profile_validation(record: dict) -> dict:
    try:
        validate_csr_for_profile(csr_for_request(record), record["profile"])
        return {"ok": True, "message": "OK"}
    except Exception as exc:
        return {"ok": False, "message": str(exc)}

