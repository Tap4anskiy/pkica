from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from pkica.config import (
    INTERMEDIATE_CERT_PATH,
    INTERMEDIATE_KEY_PATH,
    ISSUED_DB_PATH,
    ROOT_CERT_PATH,
    ROOT_KEY_PATH,
    WEB_CERT_PATH,
)
from pkica.pki.ca import (
    certificate_to_record,
    create_intermediate_ca_certificate,
    create_intermediate_csr,
    create_root_ca_certificate,
    load_certificate,
    load_issued_records,
    parse_subject,
    save_certificate,
    save_issued_records,
)
from pkica.pki.keys import generate_private_key, save_private_key
from pkica import cli
from pkica.services import audit_service
from pkica.services.certificate_service import certificate_status_counts
from pkica.services.web_service import WEB_CERT_PURPOSE, generate_web_certificate, web_certificate_status
from pkica.web import routes
from pkica.web.routes import stand_certificate_path


def test_certificate_status_counts_separates_active_expired_and_revoked() -> None:
    now = datetime.now(timezone.utc)
    records = [
        {"status": "issued", "not_valid_after": (now + timedelta(days=10)).isoformat()},
        {"status": "issued", "not_valid_after": (now - timedelta(days=1)).isoformat()},
        {"status": "revoked", "not_valid_after": (now + timedelta(days=10)).isoformat()},
    ]

    assert certificate_status_counts(records) == {"active": 1, "expired": 1, "revoked": 1}


def test_verify_path_must_stay_inside_data(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "data" / "issued").mkdir(parents=True)

    assert stand_certificate_path("data/issued/cert.pem").as_posix() == "data/issued/cert.pem"

    with pytest.raises(ValueError, match="inside data"):
        stand_certificate_path("README.md")

    with pytest.raises(ValueError, match="inside data"):
        stand_certificate_path("../data/issued/cert.pem")


def test_audit_events_can_be_filtered(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    audit_log = tmp_path / "audit.log"
    rows = [
        {
            "timestamp": "2026-05-16T10:00:00+00:00",
            "action": "cert.issue",
            "result": "success",
            "source": "web",
            "serial_number": "abc",
        },
        {
            "timestamp": "2026-05-16T10:01:00+00:00",
            "action": "verify",
            "result": "failed",
            "source": "cli",
            "reason": "bad cert",
        },
        {
            "timestamp": "2026-05-16T10:02:00+00:00",
            "action": "crl.publish",
            "result": "success",
            "source": "web",
            "revoked_count": 3,
        },
    ]
    audit_log.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
    monkeypatch.setattr(audit_service, "AUDIT_LOG_PATH", audit_log)

    assert [event["action"] for event in audit_service.list_events(source="web")] == ["cert.issue", "crl.publish"]
    assert [event["action"] for event in audit_service.list_events(result="failed")] == ["verify"]
    assert [event["action"] for event in audit_service.list_events(query="abc")] == ["cert.issue"]
    assert audit_service.event_values(rows, "source") == ["cli", "web"]


def test_audit_sources_have_defaults(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    audit_log = tmp_path / "audit.log"
    monkeypatch.setattr(audit_service, "AUDIT_LOG_PATH", audit_log)
    monkeypatch.setattr(cli, "AUDIT_LOG_PATH", audit_log)

    audit_service.log_event("service.event")
    cli.append_cli_audit({"action": "cli.event"})

    rows = audit_service.list_events()
    assert rows[0]["source"] == "service"
    assert rows[1]["source"] == "cli"


def create_test_ca() -> None:
    root_key = generate_private_key("rsa", 2048)
    root_cert = create_root_ca_certificate(root_key, parse_subject("C=RU,O=Test CA,CN=Test Root CA"), 3650)
    save_private_key(root_key, ROOT_KEY_PATH)
    save_certificate(root_cert, ROOT_CERT_PATH)

    intermediate_key = generate_private_key("rsa", 2048)
    intermediate_csr = create_intermediate_csr(
        intermediate_key,
        parse_subject("C=RU,O=Test CA,CN=Test Intermediate CA"),
    )
    intermediate_cert = create_intermediate_ca_certificate(root_key, root_cert, intermediate_csr, 1825, 0)
    save_private_key(intermediate_key, INTERMEDIATE_KEY_PATH)
    save_certificate(intermediate_cert, INTERMEDIATE_CERT_PATH)


def test_web_certificate_is_registered_and_reused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    create_test_ca()

    generate_web_certificate("pkica.local")
    first_serial = WEB_CERT_PATH.read_bytes()
    records = load_issued_records(ISSUED_DB_PATH)

    assert len(records) == 1
    assert records[0]["purpose"] == WEB_CERT_PURPOSE
    assert records[0]["cert_path"] == "data/web/certs/pkica-web.crt.pem"
    assert web_certificate_status("pkica.local")["usable"] is True

    generate_web_certificate("pkica.local")

    assert WEB_CERT_PATH.read_bytes() == first_serial
    assert len(load_issued_records(ISSUED_DB_PATH)) == 1


def test_old_revoked_web_record_does_not_block_current_certificate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    create_test_ca()
    generate_web_certificate("pkica.local")

    current_record = load_issued_records(ISSUED_DB_PATH)[0]
    old_cert = load_certificate(WEB_CERT_PATH)
    old_record = certificate_to_record(
        old_cert,
        "server_tls",
        Path("data/web/certs/old-pkica-web.crt.pem"),
        Path("data/web/certs/old-pkica-web.fullchain.pem"),
    )
    old_record["serial_number"] = "deadbeef"
    old_record["purpose"] = WEB_CERT_PURPOSE
    old_record["status"] = "revoked"
    save_issued_records(ISSUED_DB_PATH, [old_record, current_record])

    assert web_certificate_status("pkica.local")["usable"] is True


def test_certificate_registry_sort_and_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    records = []
    for index in range(26):
        records.append(
            {
                "serial_number": f"{index:02x}",
                "subject": f"CN=cert-{25 - index:02d}",
                "profile": "server_tls",
                "display_status": "active",
                "not_valid_before": f"2026-01-{index + 1:02d}T00:00:00+00:00",
                "not_valid_after": "2026-06-01T00:00:00+00:00",
            }
        )
    monkeypatch.setattr(routes, "list_certificates", lambda: records)

    assert len(routes.prepare_certificate_registry("issued_desc", "25")) == 25
    assert routes.prepare_certificate_registry("issued_desc", "25")[0]["serial_number"] == "19"
    assert routes.prepare_certificate_registry("subject_asc", "all")[0]["subject"] == "CN=cert-00"
