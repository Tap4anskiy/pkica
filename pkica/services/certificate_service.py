from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path

from pkica.config import (
    CRL_PATH,
    INTERMEDIATE_CERT_PATH,
    INTERMEDIATE_KEY_PATH,
    ISSUED_DB_PATH,
    ISSUED_DIR,
    REVOKED_DB_PATH,
    ROOT_CERT_PATH,
    REQUESTS_DB_PATH,
    ensure_ca_directories,
)
from pkica.pki.ca import (
    append_issued_record,
    certificate_to_record,
    create_end_entity_certificate,
    find_issued_record_by_serial,
    load_certificate,
    load_issued_records,
    save_certificate,
    save_fullchain,
    mark_issued_record_revoked,
)
from pkica.pki.csr import load_csr
from pkica.pki.inspect import get_cn, get_eku_text, get_san_text
from pkica.pki.keys import load_private_key
from pkica.pki.verify import verify_certificate_chain
from pkica.policy.profiles import build_end_entity_extensions, validate_csr_for_profile
from pkica.storage.requests import mark_request_issued
from pkica.storage.revocations import add_revocation
from pkica.services.audit_service import log_event
from pkica.services.request_service import get_request


def certificate_display_status(record: dict, now: datetime | None = None) -> str:
    if record.get("status") == "revoked":
        return "revoked"

    now = now or datetime.now(timezone.utc)
    try:
        expires = datetime.fromisoformat(record["not_valid_after"])
    except Exception:
        return record.get("status", "unknown")

    return "expired" if now > expires else "active"


def certificate_status_counts(records: list[dict]) -> dict[str, int]:
    now = datetime.now(timezone.utc)
    result: dict[str, int] = {}
    for record in records:
        status = certificate_display_status(record, now)
        result[status] = result.get(status, 0) + 1
    return result


def list_certificates(status: str | None = None, profile: str | None = None) -> list[dict]:
    records = load_issued_records(ISSUED_DB_PATH)
    now = datetime.now(timezone.utc)
    for record in records:
        record["display_status"] = certificate_display_status(record, now)
    if status:
        records = [record for record in records if record.get("status") == status]
    if profile:
        records = [record for record in records if record.get("profile") == profile]
    return records


def get_certificate(serial: str) -> dict:
    record = find_issued_record_by_serial(ISSUED_DB_PATH, serial)
    cert = load_certificate(Path(record["cert_path"]))
    return {
        **record,
        "serial_number": format(cert.serial_number, "x"),
        "subject": cert.subject.rfc4514_string(),
        "subject_cn": get_cn(cert.subject),
        "issuer": cert.issuer.rfc4514_string(),
        "issuer_cn": get_cn(cert.issuer),
        "not_valid_before": cert.not_valid_before_utc.isoformat(),
        "not_valid_after": cert.not_valid_after_utc.isoformat(),
        "san": get_san_text(cert),
        "eku": get_eku_text(cert),
    }


def issue_certificate_from_request(request_id: int, days: int = 365, *, source: str = "service") -> dict:
    request = get_request(request_id)
    if request["status"] != "approved":
        raise ValueError(f"Request must be approved before issuing. Current status: {request['status']}")
    return issue_certificate_from_csr(Path(request["stored_csr_path"]), request["profile"], days, request_id, source=source)


def issue_certificate_from_csr(
    csr_path: Path,
    profile: str,
    days: int = 365,
    request_id: int | None = None,
    *,
    source: str = "service",
) -> dict:
    ensure_ca_directories()
    if not INTERMEDIATE_KEY_PATH.exists() or not INTERMEDIATE_CERT_PATH.exists():
        raise ValueError("Intermediate CA is not initialized.")
    if not ROOT_CERT_PATH.exists():
        raise ValueError("Root CA certificate not found.")

    csr = load_csr(csr_path)
    validate_csr_for_profile(csr, profile)
    intermediate_key = load_private_key(INTERMEDIATE_KEY_PATH)
    intermediate_cert = load_certificate(INTERMEDIATE_CERT_PATH)
    root_cert = load_certificate(ROOT_CERT_PATH)
    cert = create_end_entity_certificate(
        intermediate_private_key=intermediate_key,
        intermediate_cert=intermediate_cert,
        csr=csr,
        days=days,
        extensions=build_end_entity_extensions(csr, profile),
    )

    serial_hex = format(cert.serial_number, "x")
    cert_path = ISSUED_DIR / f"{serial_hex}.crt.pem"
    fullchain_path = ISSUED_DIR / f"{serial_hex}.fullchain.pem"
    if cert_path.exists() or fullchain_path.exists():
        raise ValueError("Certificate file already exists. Refusing to overwrite.")

    save_certificate(cert, cert_path)
    save_fullchain(cert, intermediate_cert, root_cert, fullchain_path)
    record = certificate_to_record(cert, profile, cert_path, fullchain_path)
    if request_id is not None:
        record["request_id"] = request_id
    append_issued_record(ISSUED_DB_PATH, record)
    if request_id is not None:
        mark_request_issued(REQUESTS_DB_PATH, request_id, serial_hex)
    log_event("cert.issue", request_id=request_id, serial_number=serial_hex, profile=profile, source=source)
    return record


def revoke_certificate(serial: str, reason: str = "unspecified", *, source: str = "service") -> dict:
    record = find_issued_record_by_serial(ISSUED_DB_PATH, serial)
    if record.get("status") == "revoked":
        raise ValueError(f"Certificate already revoked: {serial}")
    revocation = add_revocation(REVOKED_DB_PATH, record["serial_number"], reason, record["cert_path"])
    updated = mark_issued_record_revoked(ISSUED_DB_PATH, record["serial_number"], reason, revocation["revoked_at"])
    log_event("cert.revoke", serial_number=updated["serial_number"], reason=reason, source=source)
    return updated


def verify_certificate_path(cert_path: Path, *, check_crl: bool = True, source: str = "service") -> dict:
    crl_path = CRL_PATH if check_crl and CRL_PATH.exists() else None
    try:
        result = verify_certificate_chain(cert_path, INTERMEDIATE_CERT_PATH, ROOT_CERT_PATH, crl_path=crl_path)
        log_event("verify", serial_number=result["serial_number"], result="success", source=source)
        return result
    except Exception as exc:
        log_event("verify", result="failed", cert_path=str(cert_path), reason=str(exc), source=source)
        raise


def verify_certificate_pem(cert_pem: str, *, check_crl: bool = True, source: str = "web") -> dict:
    with tempfile.NamedTemporaryFile("w", suffix=".crt.pem", delete=False, encoding="utf-8") as handle:
        handle.write(cert_pem)
        temp_path = Path(handle.name)
    try:
        return verify_certificate_path(temp_path, check_crl=check_crl, source=source)
    finally:
        temp_path.unlink(missing_ok=True)
