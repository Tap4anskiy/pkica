from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json

import pytest

from pkica.services import audit_service
from pkica.services.certificate_service import certificate_status_counts
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
        {"timestamp": "2026-05-16T10:00:00+00:00", "action": "cert.issue", "result": "success", "source": "web", "serial_number": "abc"},
        {"timestamp": "2026-05-16T10:01:00+00:00", "action": "verify", "result": "failed", "source": "cli", "reason": "bad cert"},
        {"timestamp": "2026-05-16T10:02:00+00:00", "action": "crl.publish", "result": "success", "source": "web", "revoked_count": 3},
    ]
    audit_log.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
    monkeypatch.setattr(audit_service, "AUDIT_LOG_PATH", audit_log)

    assert [event["action"] for event in audit_service.list_events(source="web")] == ["cert.issue", "crl.publish"]
    assert [event["action"] for event in audit_service.list_events(result="failed")] == ["verify"]
    assert [event["action"] for event in audit_service.list_events(query="abc")] == ["cert.issue"]
    assert audit_service.event_values(rows, "source") == ["cli", "web"]
