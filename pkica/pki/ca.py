from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID, ExtensionOID

from pkica.pki.keys import PrivateKey

import json



"""Получение текущего времени по UTC"""
def utcnow() -> datetime:
    return datetime.now(timezone.utc)

"""
    Преобразует строку вида:
    C=RU,O=My Org,CN=My CA,...
    в объект x509.Name.
"""
def parse_subject(subject_str: str) -> x509.Name:
    # Словарь соответсвий
    oid_map = {
        "C": NameOID.COUNTRY_NAME,
        "ST": NameOID.STATE_OR_PROVINCE_NAME,
        "L": NameOID.LOCALITY_NAME,
        "O": NameOID.ORGANIZATION_NAME,
        "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
        "CN": NameOID.COMMON_NAME,
        "EMAIL": NameOID.EMAIL_ADDRESS,
    }

    # Инициализация списка атрибутов
    attributes: list[x509.NameAttribute] = []

    # Цикл разбиения исходной строки и заполнения списка атрибутов
    for raw_part in subject_str.split(","):
        part = raw_part.strip()
        if "=" not in part:
            raise ValueError(f"Invalid subject component: {part}")

        key, value = part.split("=", 1)
        key = key.strip().upper()
        value = value.strip()

        if key not in oid_map:
            raise ValueError(f"Unsupported subject field: {key}")

        attributes.append(x509.NameAttribute(oid_map[key], value))

    if not attributes:
        raise ValueError("Subject must not be empty")

    return x509.Name(attributes)


"""Сохраняет сертификат в PEM"""
def save_certificate(cert: x509.Certificate, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


"""Создаёт self-signed сертификат Root CA"""
def create_root_ca_certificate(
    private_key: PrivateKey,
    subject: x509.Name,
    days: int,
) -> x509.Certificate:
    now = utcnow()

    # Создание и заполнение шаблона сертификата
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=1),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
    )

    # Подпись и возврат сертификата
    return builder.sign(private_key=private_key, algorithm=hashes.SHA256())


"""Создаёт CSR для Intermediate CA"""
def create_intermediate_csr(
    private_key: PrivateKey,
    subject: x509.Name,
) -> x509.CertificateSigningRequest:
    # Создание CSR для Int CA
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
    # Подпись CSR закрытым ключом Int CA и возврат
    return csr_builder.sign(private_key, hashes.SHA256())


"""Сохраняет CSR в PEM"""
def save_csr(csr: x509.CertificateSigningRequest, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))


"""Подписывает CSR промежуточного УЦ корневым ключом"""
def create_intermediate_ca_certificate(
    root_private_key: PrivateKey,
    root_cert: x509.Certificate,
    intermediate_csr: x509.CertificateSigningRequest,
    days: int,
    pathlen: int,
) -> x509.Certificate:
    now = utcnow()
    # Извлечение public key из CSR
    public_key = intermediate_csr.public_key()

    not_after = now + timedelta(days=days)

    # Проверка, чтобы срок действия Int не превышал Root
    if not_after > root_cert.not_valid_after_utc:
        raise ValueError("Intermediate certificate cannot outlive the root certificate")
    
    # Создание и заполнение шаблона сертификата Int CA
    builder = (
        x509.CertificateBuilder()
        .subject_name(intermediate_csr.subject)
        .issuer_name(root_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=pathlen),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_private_key.public_key()),
            critical=False,
        )
    )

    # Подпись Int CA
    return builder.sign(private_key=root_private_key, algorithm=hashes.SHA256())


"""Загружает PEM-сертификат"""
def load_certificate(path: Path) -> x509.Certificate:
    data = path.read_bytes()
    return x509.load_pem_x509_certificate(data)

def create_end_entity_certificate(
    intermediate_private_key: PrivateKey,
    intermediate_cert: x509.Certificate,
    csr: x509.CertificateSigningRequest,
    days: int,
    extensions: list[tuple[x509.ExtensionType, bool]],
) -> x509.Certificate:
    """Выпускает конечный сертификат по CSR."""
    now = utcnow()

    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(intermediate_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
    )

    for extension, critical in extensions:
        builder = builder.add_extension(extension, critical=critical)

    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(
            intermediate_private_key.public_key()
        ),
        critical=False,
    )

    return builder.sign(
        private_key=intermediate_private_key,
        algorithm=hashes.SHA256(),
    )


def certificate_to_record(
    cert: x509.Certificate,
    profile: str,
    cert_path: Path,
    fullchain_path: Path,
) -> dict:
    """Формирует запись для реестра выданных сертификатов."""
    return {
        "serial_number": format(cert.serial_number, "x"),
        "profile": profile,
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_valid_before": cert.not_valid_before_utc.isoformat(),
        "not_valid_after": cert.not_valid_after_utc.isoformat(),
        "cert_path": str(cert_path),
        "fullchain_path": str(fullchain_path),
        "status": "issued",
    }


def append_issued_record(db_path: Path, record: dict) -> None:
    """Добавляет запись о выданном сертификате в JSON-реестр."""
    db_path.parent.mkdir(parents=True, exist_ok=True)

    if db_path.exists():
        records = json.loads(db_path.read_text(encoding="utf-8"))
    else:
        records = []

    records.append(record)
    db_path.write_text(
        json.dumps(records, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def save_fullchain(
    cert: x509.Certificate,
    intermediate_cert: x509.Certificate,
    root_cert: x509.Certificate,
    output_path: Path,
) -> None:
    """Сохраняет fullchain: конечный сертификат + Intermediate + Root."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    data = (
        cert.public_bytes(serialization.Encoding.PEM)
        + intermediate_cert.public_bytes(serialization.Encoding.PEM)
        + root_cert.public_bytes(serialization.Encoding.PEM)
    )

    output_path.write_bytes(data)

def load_issued_records(db_path: Path) -> list[dict]:
    """Загружает реестр выданных сертификатов."""
    if not db_path.exists():
        return []

    return json.loads(db_path.read_text(encoding="utf-8"))


def find_issued_record_by_serial(db_path: Path, serial_number: str) -> dict:
    """Ищет запись о сертификате по серийному номеру."""
    records = load_issued_records(db_path)
    serial_number = serial_number.lower().replace("0x", "")

    for record in records:
        if record["serial_number"].lower().replace("0x", "") == serial_number:
            return record

    raise ValueError(f"Certificate not found by serial: {serial_number}")


def find_issued_record_by_request_id(db_path: Path, request_id: int) -> dict:
    """Ищет запись о сертификате по ID заявки."""
    records = load_issued_records(db_path)

    for record in records:
        if record.get("request_id") == request_id:
            return record

    raise ValueError(f"Certificate not found by request ID: {request_id}")

def save_issued_records(db_path: Path, records: list[dict]) -> None:
    """Сохраняет реестр выданных сертификатов."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.write_text(
        json.dumps(records, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def mark_issued_record_revoked(
    db_path: Path,
    serial_number: str,
    reason: str,
    revoked_at: str,
) -> dict:
    """Помечает выданный сертификат как отозванный."""
    records = load_issued_records(db_path)
    serial_number = serial_number.lower().replace("0x", "")

    for record in records:
        if record["serial_number"].lower().replace("0x", "") == serial_number:
            if record.get("status") == "revoked":
                raise ValueError(f"Certificate already revoked: {serial_number}")

            record["status"] = "revoked"
            record["revoked_at"] = revoked_at
            record["revocation_reason"] = reason

            save_issued_records(db_path, records)
            return record

    raise ValueError(f"Certificate not found by serial: {serial_number}")