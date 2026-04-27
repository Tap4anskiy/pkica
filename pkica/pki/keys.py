from __future__ import annotations

from pathlib import Path
from typing import Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from pkica.storage.secure import write_private_bytes

# Псевдотипы
PrivateKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
KeyAlgorithm = Literal["rsa", "ecdsa"]


"""Генерирует закрытый ключ RSA или ECDSA"""
def generate_private_key(algorithm: KeyAlgorithm, rsa_bits: int = 4096) -> PrivateKey:
    if algorithm == "rsa":
        if algorithm == "rsa" and rsa_bits < 2048:
            raise ValueError("RSA key size must be at least 2048 bits")
        return rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)

    if algorithm == "ecdsa":
        return ec.generate_private_key(ec.SECP256R1())

    raise ValueError(f"Unsupported algorithm: {algorithm}")


"""Сохраняет закрытый ключ в PEM"""
def save_private_key(
    private_key: PrivateKey,
    output_path: Path,
    password: str | None = None,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Выбор режима шифрования
    if password:
        encryption = serialization.BestAvailableEncryption(password.encode("utf-8"))
    else:
        encryption = serialization.NoEncryption()

    # Сериализация
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )

    # Запись в файл
    write_private_bytes(output_path, pem)


"""Загружает закрытый ключ из PEM"""
def load_private_key(path: Path, password: str | None = None) -> PrivateKey:
    data = path.read_bytes()
    return serialization.load_pem_private_key(
        data,
        password=password.encode("utf-8") if password else None,
    )
