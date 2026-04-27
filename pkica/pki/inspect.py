from __future__ import annotations

import ipaddress

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID, NameOID


def get_cn(name: x509.Name) -> str | None:
    values = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not values:
        return None
    return values[0].value


def get_san_text(cert: x509.Certificate) -> str:
    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
    except x509.ExtensionNotFound:
        return "-"

    parts: list[str] = []

    for dns in san.get_values_for_type(x509.DNSName):
        parts.append(f"DNS:{dns}")

    for ip in san.get_values_for_type(x509.IPAddress):
        if isinstance(ip, ipaddress.IPv4Address | ipaddress.IPv6Address):
            parts.append(f"IP:{ip}")

    return ", ".join(parts) if parts else "-"


def get_eku_text(cert: x509.Certificate) -> str:
    try:
        eku = cert.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE
        ).value
    except x509.ExtensionNotFound:
        return "-"

    names = []

    for oid in eku:
        if oid == ExtendedKeyUsageOID.SERVER_AUTH:
            names.append("serverAuth")
        elif oid == ExtendedKeyUsageOID.CLIENT_AUTH:
            names.append("clientAuth")
        else:
            names.append(oid.dotted_string)

    return ", ".join(names) if names else "-"


def get_basic_constraints_text(cert: x509.Certificate) -> str:
    try:
        bc = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
    except x509.ExtensionNotFound:
        return "-"

    if bc.ca:
        return f"CA:TRUE, pathlen:{bc.path_length}"
    return "CA:FALSE"


def get_key_usage_text(cert: x509.Certificate) -> str:
    try:
        ku = cert.extensions.get_extension_for_oid(
            ExtensionOID.KEY_USAGE
        ).value
    except x509.ExtensionNotFound:
        return "-"

    values = []

    if ku.digital_signature:
        values.append("digitalSignature")
    if ku.content_commitment:
        values.append("contentCommitment")
    if ku.key_encipherment:
        values.append("keyEncipherment")
    if ku.data_encipherment:
        values.append("dataEncipherment")
    if ku.key_agreement:
        values.append("keyAgreement")
    if ku.key_cert_sign:
        values.append("keyCertSign")
    if ku.crl_sign:
        values.append("cRLSign")

    return ", ".join(values) if values else "-"