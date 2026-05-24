from __future__ import annotations

import argparse
import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from fastapi import HTTPException

from pkica.config import (
    INTERMEDIATE_CERT_PATH,
    INTERMEDIATE_KEY_PATH,
    CRL_PATH,
    ISSUED_DB_PATH,
    REVOKED_DB_PATH,
    ROOT_CERT_PATH,
    ROOT_KEY_PATH,
    TRUST_EXPORT_DIR,
    WEB_AUTH_PATH,
    WEB_CERT_PATH,
    WEB_DIR,
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
from pkica.services import auth_service
from pkica.services import crl_service
from pkica.services import trust_service
from pkica.services.certificate_service import certificate_status_counts
from pkica.services.web_service import WEB_CERT_PURPOSE, generate_web_certificate, web_certificate_info, web_certificate_status
from pkica.web.app import app
from pkica.web import routes
from pkica.web.routes import stand_certificate_path


def run_async(coro):
    return asyncio.run(coro)


async def login_admin_client(username: str, password: str) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app)
    client = httpx.AsyncClient(transport=transport, base_url="https://testserver", follow_redirects=False)
    response = await client.post("/admin/login", data={"username": username, "password": password})
    assert response.status_code == 303
    assert response.headers["location"] == "/admin"
    return client


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


def test_admin_credentials_are_generated_and_sessions_are_signed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)

    created = auth_service.ensure_admin_credentials()

    assert created["generated"] is True
    assert created["username"].startswith("admin-")
    assert created["password"]
    assert WEB_AUTH_PATH.exists()
    assert created["password"] not in WEB_AUTH_PATH.read_text(encoding="utf-8")
    assert auth_service.authenticate(created["username"], created["password"]) is True
    assert auth_service.authenticate(created["username"], "bad-password") is False

    cookie = auth_service.create_session_cookie(created["username"])
    assert auth_service.verify_session_cookie(cookie) is True
    assert auth_service.verify_session_cookie(f"{cookie}x") is False

    reused = auth_service.ensure_admin_credentials()
    assert reused == {"username": created["username"], "password": None, "generated": False}


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


def test_web_reset_revokes_certificate_and_removes_web_data(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    create_test_ca()
    generate_web_certificate("pkica.local")
    auth_service.ensure_admin_credentials()

    assert WEB_CERT_PATH.exists()
    assert WEB_AUTH_PATH.exists()
    assert cli.command_web_reset(argparse.Namespace(force=True, reason="cessationOfOperation")) == 0

    output = capsys.readouterr().out
    assert "pkica web reset successfully." in output
    assert "Web certificate revoked: 1" in output
    assert not WEB_DIR.exists()

    issued = load_issued_records(ISSUED_DB_PATH)
    assert issued[0]["status"] == "revoked"
    assert issued[0]["revocation_reason"] == "cessationOfOperation"

    revoked = json.loads(REVOKED_DB_PATH.read_text(encoding="utf-8"))
    assert revoked[0]["serial_number"] == issued[0]["serial_number"]
    assert revoked[0]["reason"] == "cessationOfOperation"


def test_web_certificate_info_is_printable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.chdir(tmp_path)
    create_test_ca()
    generate_web_certificate("pkica.local")

    info = web_certificate_info()
    assert info is not None
    assert info["path"] == "data/web/certs/pkica-web.crt.pem"
    assert info["fullchain_path"] == "data/web/certs/pkica-web.fullchain.pem"

    cli.print_web_certificate_info(info)

    output = capsys.readouterr().out
    assert "Web certificate" in output
    assert "Serial:" in output
    assert "CN=pkica.local" in output


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


def test_public_and_admin_routes_are_separated() -> None:
    paths = {route.path for route in routes.router.routes}

    assert routes.root().headers["location"] == "/trust"
    assert "/trust" in paths
    assert "/trust/download/{name}" in paths
    assert "/admin" in paths
    assert "/admin/login" in paths
    assert "/admin/logout" in paths
    assert "/admin/certificates" in paths
    assert "/admin/crl" in paths
    assert "/certificates" not in paths
    assert "/crl" not in paths


def test_trust_center_reports_fingerprints_and_downloads(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    create_test_ca()
    crl_service.publish_crl()

    trust = trust_service.trust_center_status()

    assert trust["ready"] is True
    assert trust["warnings"] == []
    assert trust["artifacts"][0]["fingerprint_sha256"].count(":") == 31
    assert trust["chain"]["fingerprint_sha256"].count(":") == 31
    assert trust["crl"]["exists"] is True
    assert trust["crl"]["fingerprint_sha256"].count(":") == 31

    response = routes.trust_download("ca-chain.pem")
    assert response.media_type == "application/x-pem-file"
    assert response.body.startswith(INTERMEDIATE_CERT_PATH.read_bytes())
    assert response.body.endswith(ROOT_CERT_PATH.read_bytes())

    crl_response = routes.trust_download("intermediate.crl.pem")
    assert crl_response.body == CRL_PATH.read_bytes()


def test_export_trust_prints_fingerprints(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.chdir(tmp_path)
    create_test_ca()

    assert cli.command_export_trust(argparse.Namespace()) == 0

    output = capsys.readouterr().out
    assert "SHA256:" in output
    assert str(TRUST_EXPORT_DIR / "root.crt.pem") in output
    assert (TRUST_EXPORT_DIR / "ca-chain.pem").exists()


def test_public_trust_does_not_expose_local_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)

    trust = trust_service.trust_center_status()

    assert trust["warnings"] == [
        "Root CA certificate is unavailable.",
        "Intermediate CA certificate is unavailable.",
    ]
    assert "data/" not in json.dumps(trust["warnings"], ensure_ascii=False)

    with pytest.raises(Exception) as root_download:
        routes.trust_download("root.crt.pem")
    assert "data/" not in str(root_download.value)

    with pytest.raises(Exception) as chain_download:
        routes.trust_download("ca-chain.pem")
    assert "data/" not in str(chain_download.value)


def test_admin_http_login_flow_and_protection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    credentials = auth_service.ensure_admin_credentials()

    async def scenario() -> None:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="https://testserver", follow_redirects=False) as client:
            protected = await client.get("/admin")
            assert protected.status_code == 303
            assert protected.headers["location"] == "/admin/login?next=/admin"

            login = await client.post(
                "/admin/login",
                data={"username": credentials["username"], "password": credentials["password"]},
            )
            assert login.status_code == 303
            assert "httponly" in login.headers["set-cookie"].lower()

    run_async(scenario())


def test_missing_admin_objects_return_404(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)

    with pytest.raises(Exception) as missing_cert:
        routes.certificate_detail_context("missing")
    with pytest.raises(HTTPException) as cert_response:
        routes.raise_not_found(missing_cert.value)
    assert cert_response.value.status_code == 404

    with pytest.raises(Exception) as missing_request:
        routes.request_detail_context(999999)
    with pytest.raises(HTTPException) as request_response:
        routes.raise_not_found(missing_request.value)
    assert request_response.value.status_code == 404


def test_certificate_detail_context_does_not_log_verify_event(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    create_test_ca()
    generate_web_certificate("pkica.local")
    serial = load_issued_records(ISSUED_DB_PATH)[0]["serial_number"]

    before = len(audit_service.list_events(action="verify"))
    context = routes.certificate_detail_context(serial)
    after = len(audit_service.list_events(action="verify"))

    assert context["cert"]["serial_number"] == serial
    assert context["verification"]["ok"] is True
    assert after == before
