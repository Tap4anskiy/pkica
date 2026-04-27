from __future__ import annotations

import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from pkica.pki.keys import PrivateKey


def build_subject(common_name: str, organization: str | None = None, country: str | None = None) -> x509.Name:
    attributes = []

    if country:
        attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))

    if organization:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))

    attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))

    return x509.Name(attributes)


def build_san_extension(
    dns_names: list[str] | None = None,
    ip_addresses: list[str] | None = None,
) -> x509.SubjectAlternativeName | None:
    san_items: list[x509.GeneralName] = []

    for dns in dns_names or []:
        san_items.append(x509.DNSName(dns))

    for ip in ip_addresses or []:
        san_items.append(x509.IPAddress(ipaddress.ip_address(ip)))

    if not san_items:
        return None

    return x509.SubjectAlternativeName(san_items)


def create_csr(
    private_key: PrivateKey,
    common_name: str,
    organization: str | None = None,
    country: str | None = None,
    dns_names: list[str] | None = None,
    ip_addresses: list[str] | None = None,
) -> x509.CertificateSigningRequest:
    subject = build_subject(common_name, organization, country)

    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)

    san = build_san_extension(dns_names=dns_names, ip_addresses=ip_addresses)
    if san is not None:
        builder = builder.add_extension(san, critical=False)

    return builder.sign(private_key, hashes.SHA256())


def save_csr(csr: x509.CertificateSigningRequest, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))


def load_csr(path: Path) -> x509.CertificateSigningRequest:
    data = path.read_bytes()
    return x509.load_pem_x509_csr(data)