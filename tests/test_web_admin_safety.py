from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

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
