from __future__ import annotations

from pkica.config import CRL_PATH, INTERMEDIATE_CERT_PATH, INTERMEDIATE_KEY_PATH, REVOKED_DB_PATH, ensure_ca_directories
from pkica.pki.ca import load_certificate
from pkica.pki.crl import create_crl, save_crl
from pkica.pki.keys import load_private_key
from pkica.pki.verify import load_crl
from pkica.storage.revocations import load_revocations
from pkica.services.audit_service import log_event


def publish_crl(days: int = 7, *, source: str = "service") -> dict:
    ensure_ca_directories()
    if not INTERMEDIATE_KEY_PATH.exists() or not INTERMEDIATE_CERT_PATH.exists():
        raise ValueError("Intermediate CA is not initialized.")
    intermediate_key = load_private_key(INTERMEDIATE_KEY_PATH)
    intermediate_cert = load_certificate(INTERMEDIATE_CERT_PATH)
    revoked = load_revocations(REVOKED_DB_PATH)
    crl = create_crl(intermediate_cert, intermediate_key, revoked, days=days)
    save_crl(crl, CRL_PATH)
    log_event("crl.publish", crl_path=str(CRL_PATH), revoked_count=len(revoked), source=source)
    return crl_info()


def crl_info() -> dict:
    revoked = load_revocations(REVOKED_DB_PATH)
    info = {
        "path": str(CRL_PATH),
        "exists": CRL_PATH.exists(),
        "revoked": revoked,
        "revoked_count": len(revoked),
        "published_revoked_count": 0,
        "crl_outdated": False,
        "last_update": None,
        "next_update": None,
    }
    if CRL_PATH.exists():
        crl = load_crl(CRL_PATH)
        info["last_update"] = crl.last_update_utc.isoformat()
        info["next_update"] = crl.next_update_utc.isoformat()
        info["published_revoked_count"] = len(list(crl))
        info["crl_outdated"] = info["revoked_count"] > info["published_revoked_count"]
    elif revoked:
        info["crl_outdated"] = True
    return info
