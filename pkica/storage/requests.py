from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

from pkica.pki.csr import load_csr


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_requests(db_path: Path) -> list[dict]:
    if not db_path.exists():
        return []

    return json.loads(db_path.read_text(encoding="utf-8"))


def save_requests(db_path: Path, records: list[dict]) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.write_text(
        json.dumps(records, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    db_path.chmod(0o600)


def next_request_id(records: list[dict]) -> int:
    if not records:
        return 1

    return max(record["id"] for record in records) + 1


def get_subject_cn(csr: x509.CertificateSigningRequest) -> str | None:
    attributes = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attributes:
        return None

    return attributes[0].value


def get_san_values(csr: x509.CertificateSigningRequest) -> dict:
    result = {
        "dns": [],
        "ip": [],
    }

    try:
        san = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    except x509.ExtensionNotFound:
        return result

    result["dns"] = san.get_values_for_type(x509.DNSName)
    result["ip"] = [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]

    return result


def create_request_record(
    request_id: int,
    csr_path: Path,
    stored_csr_path: Path,
    profile: str,
    csr: x509.CertificateSigningRequest,
) -> dict:
    return {
        "id": request_id,
        "status": "pending",
        "profile": profile,
        "original_csr_path": str(csr_path),
        "stored_csr_path": str(stored_csr_path),
        "subject": csr.subject.rfc4514_string(),
        "cn": get_subject_cn(csr),
        "san": get_san_values(csr),
        "created_at": now_iso(),
        "approved_at": None,
        "rejected_at": None,
        "rejection_reason": None,
        "issued_at": None,
        "issued_serial_number": None,
    }


def submit_request(
    db_path: Path,
    csr_path: Path,
    requests_dir: Path,
    profile: str,
) -> dict:
    records = load_requests(db_path)
    request_id = next_request_id(records)

    csr = load_csr(csr_path)

    stored_csr_path = requests_dir / f"req-{request_id:06d}.csr.pem"
    stored_csr_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(csr_path, stored_csr_path)

    record = create_request_record(
        request_id=request_id,
        csr_path=csr_path,
        stored_csr_path=stored_csr_path,
        profile=profile,
        csr=csr,
    )

    records.append(record)
    save_requests(db_path, records)

    return record


def find_request(records: list[dict], request_id: int) -> dict:
    for record in records:
        if record["id"] == request_id:
            return record

    raise ValueError(f"Request not found: {request_id}")


def update_request_status(
    db_path: Path,
    request_id: int,
    status: str,
    reason: str | None = None,
) -> dict:
    records = load_requests(db_path)
    record = find_request(records, request_id)

    if status == "approved":
        if record["status"] != "pending":
            raise ValueError(f"Only pending requests can be approved. Current status: {record['status']}")
        record["status"] = "approved"
        record["approved_at"] = now_iso()

    elif status == "rejected":
        if record["status"] not in ["pending", "approved"]:
            raise ValueError(f"Only pending or approved requests can be rejected. Current status: {record['status']}")
        record["status"] = "rejected"
        record["rejected_at"] = now_iso()
        record["rejection_reason"] = reason

    else:
        raise ValueError(f"Unsupported request status: {status}")

    save_requests(db_path, records)
    return record


def mark_request_issued(
    db_path: Path,
    request_id: int,
    serial_number: str,
) -> dict:
    records = load_requests(db_path)
    record = find_request(records, request_id)

    if record["status"] != "approved":
        raise ValueError(f"Only approved requests can be issued. Current status: {record['status']}")

    record["status"] = "issued"
    record["issued_at"] = now_iso()
    record["issued_serial_number"] = serial_number

    save_requests(db_path, records)
    return record
