from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime, timezone

from pkica.config import WEB_AUTH_PATH
from pkica.storage.secure import ensure_private_dir, write_private_text

SESSION_COOKIE = "pkica_admin_session"
SESSION_TTL_SECONDS = 8 * 60 * 60
PBKDF2_ITERATIONS = 260_000


def b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def password_hash(password: str, salt: bytes | None = None) -> dict:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return {
        "algorithm": "pbkdf2_sha256",
        "iterations": PBKDF2_ITERATIONS,
        "salt": b64encode(salt),
        "hash": b64encode(digest),
    }


def verify_password(password: str, auth: dict) -> bool:
    try:
        expected = b64decode(auth["password"]["hash"])
        salt = b64decode(auth["password"]["salt"])
        iterations = int(auth["password"]["iterations"])
    except Exception:
        return False

    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(digest, expected)


def read_auth_config() -> dict | None:
    if not WEB_AUTH_PATH.exists():
        return None
    try:
        return json.loads(WEB_AUTH_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def write_auth_config(auth: dict) -> None:
    ensure_private_dir(WEB_AUTH_PATH.parent)
    write_private_text(WEB_AUTH_PATH, json.dumps(auth, indent=2, sort_keys=True))


def generate_admin_credentials() -> dict:
    username = f"admin-{secrets.token_urlsafe(8)}"
    password = secrets.token_urlsafe(32)
    auth = {
        "username": username,
        "password": password_hash(password),
        "session_secret": b64encode(secrets.token_bytes(32)),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    write_auth_config(auth)
    return {"username": username, "password": password, "generated": True}


def ensure_admin_credentials() -> dict:
    auth = read_auth_config()
    if auth is None:
        return generate_admin_credentials()
    return {"username": auth.get("username", "-"), "password": None, "generated": False}


def authenticate(username: str, password: str) -> bool:
    auth = read_auth_config()
    if not auth:
        return False
    if not hmac.compare_digest(username, str(auth.get("username", ""))):
        return False
    return verify_password(password, auth)


def session_signature(secret: bytes, payload: str) -> str:
    return b64encode(hmac.new(secret, payload.encode("utf-8"), hashlib.sha256).digest())


def create_session_cookie(username: str) -> str:
    auth = read_auth_config()
    if not auth:
        raise ValueError("Admin credentials are not initialized.")
    expires_at = int(time.time()) + SESSION_TTL_SECONDS
    nonce = secrets.token_urlsafe(16)
    payload = f"{username}:{expires_at}:{nonce}"
    signature = session_signature(b64decode(auth["session_secret"]), payload)
    return f"{payload}:{signature}"


def verify_session_cookie(cookie: str | None) -> bool:
    if not cookie:
        return False
    auth = read_auth_config()
    if not auth:
        return False
    try:
        username, expires_at_text, nonce, signature = cookie.split(":", 3)
        expires_at = int(expires_at_text)
    except ValueError:
        return False
    if username != auth.get("username"):
        return False
    if expires_at < int(time.time()):
        return False
    payload = f"{username}:{expires_at}:{nonce}"
    expected = session_signature(b64decode(auth["session_secret"]), payload)
    return hmac.compare_digest(signature, expected)
