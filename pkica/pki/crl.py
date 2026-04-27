from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import CRLEntryExtensionOID

from pkica.pki.keys import PrivateKey


REASON_MAP = {
    "unspecified": x509.ReasonFlags.unspecified,
    "keyCompromise": x509.ReasonFlags.key_compromise,
    "caCompromise": x509.ReasonFlags.ca_compromise,
    "affiliationChanged": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessationOfOperation": x509.ReasonFlags.cessation_of_operation,
    "certificateHold": x509.ReasonFlags.certificate_hold,
    "privilegeWithdrawn": x509.ReasonFlags.privilege_withdrawn,
    "aaCompromise": x509.ReasonFlags.aa_compromise,
}


def parse_iso_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value)


def create_crl(
    issuer_cert: x509.Certificate,
    issuer_private_key: PrivateKey,
    revoked_records: list[dict],
    days: int = 7,
) -> x509.CertificateRevocationList:
    now = datetime.now(timezone.utc)

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_cert.subject)
        .last_update(now)
        .next_update(now + timedelta(days=days))
    )

    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(
            issuer_private_key.public_key()
        ),
        critical=False,
    )

    for record in revoked_records:
        reason_name = record.get("reason", "unspecified")
        reason = REASON_MAP.get(reason_name, x509.ReasonFlags.unspecified)

        revoked_at = parse_iso_datetime(record["revoked_at"])

        revoked_cert = (
            x509.RevokedCertificateBuilder()
            .serial_number(int(record["serial_number"], 16))
            .revocation_date(revoked_at)
            .add_extension(
                x509.CRLReason(reason),
                critical=False,
            )
            .build()
        )

        builder = builder.add_revoked_certificate(revoked_cert)

    return builder.sign(
        private_key=issuer_private_key,
        algorithm=hashes.SHA256(),
    )


def save_crl(crl: x509.CertificateRevocationList, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(crl.public_bytes(serialization.Encoding.PEM))