from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

from pkica.pki.ca import load_certificate


def load_crl(path: Path) -> x509.CertificateRevocationList:
    data = path.read_bytes()
    return x509.load_pem_x509_crl(data)


def verify_signature(
    cert: x509.Certificate,
    issuer_cert: x509.Certificate,
) -> None:
    issuer_public_key = issuer_cert.public_key()

    if isinstance(issuer_public_key, rsa.RSAPublicKey):
        issuer_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        return

    if isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
        issuer_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(cert.signature_hash_algorithm),
        )
        return

    raise ValueError("Unsupported issuer public key type")


def check_validity_period(cert: x509.Certificate) -> None:
    now = datetime.now(timezone.utc)

    if now < cert.not_valid_before_utc:
        raise ValueError("Certificate is not valid yet")

    if now > cert.not_valid_after_utc:
        raise ValueError("Certificate has expired")


def check_crl_signature(
    crl: x509.CertificateRevocationList,
    issuer_cert: x509.Certificate,
) -> None:
    issuer_public_key = issuer_cert.public_key()

    if isinstance(issuer_public_key, rsa.RSAPublicKey):
        issuer_public_key.verify(
            crl.signature,
            crl.tbs_certlist_bytes,
            PKCS1v15(),
            crl.signature_hash_algorithm,
        )
        return

    if isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
        issuer_public_key.verify(
            crl.signature,
            crl.tbs_certlist_bytes,
            ec.ECDSA(crl.signature_hash_algorithm),
        )
        return

    raise ValueError("Unsupported CRL issuer public key type")


def check_certificate_not_revoked(
    cert: x509.Certificate,
    crl: x509.CertificateRevocationList,
) -> None:
    for revoked_cert in crl:
        if revoked_cert.serial_number == cert.serial_number:
            raise ValueError("Certificate is revoked")


def verify_certificate_chain(
    cert_path: Path,
    intermediate_cert_path: Path,
    root_cert_path: Path,
    crl_path: Path | None = None,
) -> dict:
    cert = load_certificate(cert_path)
    intermediate_cert = load_certificate(intermediate_cert_path)
    root_cert = load_certificate(root_cert_path)

    check_validity_period(cert)
    check_validity_period(intermediate_cert)
    check_validity_period(root_cert)

    verify_signature(cert, intermediate_cert)
    verify_signature(intermediate_cert, root_cert)
    verify_signature(root_cert, root_cert)

    result = {
        "serial_number": format(cert.serial_number, "x"),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "chain_valid": True,
        "revoked": False,
        "crl_checked": False,
    }

    if crl_path is not None:
        crl = load_crl(crl_path)
        check_crl_signature(crl, intermediate_cert)
        check_certificate_not_revoked(cert, crl)

        result["crl_checked"] = True

    return result