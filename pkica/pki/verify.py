from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

from pkica.pki.ca import load_certificate


def load_crl(path: Path) -> x509.CertificateRevocationList:
    data = path.read_bytes()
    return x509.load_pem_x509_crl(data)


def get_name_for_chain(name: x509.Name) -> str:
    common_names = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if common_names:
        return common_names[0].value
    return name.rfc4514_string()


def format_trust_chain(*certs: x509.Certificate) -> str:
    return " -> ".join(get_name_for_chain(cert.subject) for cert in certs)


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


def check_issuer_subject(cert: x509.Certificate, issuer_cert: x509.Certificate) -> None:
    if cert.issuer != issuer_cert.subject:
        raise ValueError("Certificate issuer does not match issuer certificate subject")


def get_basic_constraints_extension(cert: x509.Certificate) -> x509.Extension:
    try:
        return cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
    except x509.ExtensionNotFound as exc:
        raise ValueError("Certificate is missing BasicConstraints") from exc


def get_basic_constraints(cert: x509.Certificate) -> x509.BasicConstraints:
    return get_basic_constraints_extension(cert).value


def get_key_usage_extension(cert: x509.Certificate) -> x509.Extension:
    try:
        return cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
    except x509.ExtensionNotFound as exc:
        raise ValueError("Certificate is missing KeyUsage") from exc


def get_key_usage(cert: x509.Certificate) -> x509.KeyUsage:
    return get_key_usage_extension(cert).value


def get_extended_key_usage(cert: x509.Certificate) -> x509.ExtendedKeyUsage:
    try:
        return cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("End-entity certificate is missing ExtendedKeyUsage") from exc


def check_ca_certificate(cert: x509.Certificate, name: str) -> None:
    basic_constraints_extension = get_basic_constraints_extension(cert)
    if not basic_constraints_extension.critical:
        raise ValueError(f"{name} certificate BasicConstraints must be critical")

    basic_constraints = basic_constraints_extension.value
    if not basic_constraints.ca:
        raise ValueError(f"{name} certificate must have CA:TRUE")

    key_usage_extension = get_key_usage_extension(cert)
    if not key_usage_extension.critical:
        raise ValueError(f"{name} certificate KeyUsage must be critical")

    key_usage = key_usage_extension.value
    if not key_usage.key_cert_sign:
        raise ValueError(f"{name} certificate must allow keyCertSign")
    if not key_usage.crl_sign:
        raise ValueError(f"{name} certificate must allow cRLSign")


def check_end_entity_certificate(cert: x509.Certificate) -> None:
    basic_constraints_extension = get_basic_constraints_extension(cert)
    if not basic_constraints_extension.critical:
        raise ValueError("End-entity certificate BasicConstraints must be critical")

    basic_constraints = basic_constraints_extension.value
    if basic_constraints.ca:
        raise ValueError("End-entity certificate must have CA:FALSE")

    key_usage_extension = get_key_usage_extension(cert)
    if not key_usage_extension.critical:
        raise ValueError("End-entity certificate KeyUsage must be critical")

    key_usage = key_usage_extension.value
    if key_usage.key_cert_sign or key_usage.crl_sign:
        raise ValueError("End-entity certificate must not allow CA signing usages")

    eku = get_extended_key_usage(cert)
    allowed_eku = {
        ExtendedKeyUsageOID.SERVER_AUTH,
        ExtendedKeyUsageOID.CLIENT_AUTH,
    }
    if not any(oid in eku for oid in allowed_eku):
        raise ValueError("End-entity certificate must allow serverAuth or clientAuth")


def check_path_length(root_cert: x509.Certificate, intermediate_cert: x509.Certificate) -> None:
    root_bc = get_basic_constraints(root_cert)
    intermediate_bc = get_basic_constraints(intermediate_cert)

    if root_bc.path_length is not None and root_bc.path_length < 1:
        raise ValueError("Root certificate path length does not allow an intermediate CA")

    if intermediate_bc.path_length is not None and intermediate_bc.path_length < 0:
        raise ValueError("Intermediate certificate path length is invalid")


def check_leaf_within_issuer_validity(cert: x509.Certificate, issuer_cert: x509.Certificate) -> None:
    if cert.not_valid_before_utc < issuer_cert.not_valid_before_utc:
        raise ValueError("Certificate is valid before issuer certificate")

    if cert.not_valid_after_utc > issuer_cert.not_valid_after_utc:
        raise ValueError("Certificate outlives issuer certificate")


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


def check_crl_metadata(crl: x509.CertificateRevocationList, issuer_cert: x509.Certificate) -> None:
    now = datetime.now(timezone.utc)

    if crl.issuer != issuer_cert.subject:
        raise ValueError("CRL issuer does not match intermediate certificate subject")

    if now < crl.last_update_utc:
        raise ValueError("CRL is not valid yet")

    if now > crl.next_update_utc:
        raise ValueError("CRL has expired")


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

    check_issuer_subject(cert, intermediate_cert)
    check_issuer_subject(intermediate_cert, root_cert)
    check_issuer_subject(root_cert, root_cert)

    check_ca_certificate(root_cert, "Root")
    check_ca_certificate(intermediate_cert, "Intermediate")
    check_end_entity_certificate(cert)
    check_path_length(root_cert, intermediate_cert)
    check_leaf_within_issuer_validity(cert, intermediate_cert)

    verify_signature(cert, intermediate_cert)
    verify_signature(intermediate_cert, root_cert)
    verify_signature(root_cert, root_cert)

    result = {
        "serial_number": format(cert.serial_number, "x"),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "chain_valid": True,
        "trust_chain": format_trust_chain(cert, intermediate_cert, root_cert),
        "revoked": False,
        "crl_checked": False,
    }

    if crl_path is not None:
        crl = load_crl(crl_path)
        check_crl_metadata(crl, intermediate_cert)
        check_crl_signature(crl, intermediate_cert)
        check_certificate_not_revoked(cert, crl)

        result["crl_checked"] = True

    return result
