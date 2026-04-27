from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID


def get_subject_alt_name(csr: x509.CertificateSigningRequest) -> x509.SubjectAlternativeName | None:
    try:
        return csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return None


def validate_csr_for_profile(csr: x509.CertificateSigningRequest, profile: str) -> None:
    if not csr.is_signature_valid:
        raise ValueError("CSR signature is invalid")

    if profile == "server_tls":
        san = get_subject_alt_name(csr)
        if san is None:
            raise ValueError("server_tls profile requires Subject Alternative Name")

    elif profile == "client_tls":
        return

    else:
        raise ValueError(f"Unsupported certificate profile: {profile}")


def build_end_entity_extensions(
    csr: x509.CertificateSigningRequest,
    profile: str,
) -> list[tuple[x509.ExtensionType, bool]]:
    public_key = csr.public_key()

    key_encipherment = isinstance(public_key, rsa.RSAPublicKey)
    key_agreement = isinstance(public_key, ec.EllipticCurvePublicKey)

    extensions: list[tuple[x509.ExtensionType, bool]] = [
        (
            x509.BasicConstraints(ca=False, path_length=None),
            True,
        ),
        (
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=key_encipherment,
                data_encipherment=False,
                key_agreement=key_agreement,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False if key_agreement else None,
                decipher_only=False if key_agreement else None,
            ),
            True,
        ),
        (
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            False,
        ),
    ]

    san = get_subject_alt_name(csr)
    if san is not None:
        extensions.append((san, False))

    if profile == "server_tls":
        extensions.append(
            (
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                False,
            )
        )

    elif profile == "client_tls":
        extensions.append(
            (
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                False,
            )
        )

    else:
        raise ValueError(f"Unsupported certificate profile: {profile}")

    return extensions