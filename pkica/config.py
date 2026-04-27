from pathlib import Path

from pkica.storage.secure import ensure_private_dir

BASE_DIR = Path("data")

ROOT_DIR = BASE_DIR / "ca" / "root"
INTERMEDIATE_DIR = BASE_DIR / "ca" / "intermediate"

ROOT_KEY_PATH = ROOT_DIR / "private" / "root.key.pem"
ROOT_CERT_PATH = ROOT_DIR / "certs" / "root.crt.pem"

INTERMEDIATE_KEY_PATH = INTERMEDIATE_DIR / "private" / "intermediate.key.pem"
INTERMEDIATE_CSR_PATH = INTERMEDIATE_DIR / "csr" / "intermediate.csr.pem"
INTERMEDIATE_CERT_PATH = INTERMEDIATE_DIR / "certs" / "intermediate.crt.pem"

USER_KEYS_DIR = BASE_DIR / "subjects" / "keys"
USER_CSR_DIR = BASE_DIR / "subjects" / "csrs"

ISSUED_DIR = BASE_DIR / "issued"
DB_DIR = BASE_DIR / "db"
AUDIT_LOG_PATH = BASE_DIR / "audit" / "audit.log"

REQUESTS_DIR = BASE_DIR / "requests"

REQUESTS_DB_PATH = DB_DIR / "requests.json"
ISSUED_DB_PATH = DB_DIR / "issued.json"

CRL_DIR = BASE_DIR / "crl"
CRL_PATH = CRL_DIR / "intermediate.crl.pem"
REVOKED_DB_PATH = DB_DIR / "revoked.json"

EXPORT_DIR = BASE_DIR / "export"
TRUST_EXPORT_DIR = EXPORT_DIR / "trust"
NGINX_EXPORT_DIR = EXPORT_DIR / "nginx"

"""Функция проверки и создания рабочих директорий"""
def ensure_ca_directories() -> None:
    protected_dirs = [
        ROOT_DIR / "private",
        INTERMEDIATE_DIR / "private",
        USER_KEYS_DIR,
        DB_DIR,
        BASE_DIR / "audit",
    ]

    for path in [
        *protected_dirs,
        ROOT_DIR / "certs",
        INTERMEDIATE_DIR / "csr",
        INTERMEDIATE_DIR / "certs",
        USER_CSR_DIR,
        REQUESTS_DIR,
        ISSUED_DIR,
        CRL_DIR,
        EXPORT_DIR,
        TRUST_EXPORT_DIR,
        NGINX_EXPORT_DIR
    ]:
        path.mkdir(parents=True, exist_ok=True)

    for path in protected_dirs:
        ensure_private_dir(path)
