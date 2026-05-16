from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID, NameOID

from pkica.config import (
    BASE_DIR,
    ISSUED_DB_PATH,
    INTERMEDIATE_CERT_PATH,
    INTERMEDIATE_KEY_PATH,
    REVOKED_DB_PATH,
    ROOT_CERT_PATH,
    WEB_CERT_PATH,
    WEB_CSR_PATH,
    WEB_FULLCHAIN_PATH,
    WEB_KEY_PATH,
    WEB_LOG_PATH,
    WEB_NGINX_CONF_PATH,
    WEB_PID_PATH,
    WEB_STATE_PATH,
    ensure_ca_directories,
)
from pkica.pki.ca import (
    append_issued_record,
    certificate_to_record,
    create_end_entity_certificate,
    load_certificate,
    load_issued_records,
    mark_issued_record_revoked,
    save_certificate,
    save_fullchain,
    save_issued_records,
)
from pkica.pki.csr import create_csr, save_csr
from pkica.pki.keys import generate_private_key, load_private_key, save_private_key
from pkica.pki.verify import verify_certificate_chain
from pkica.policy.profiles import build_end_entity_extensions, validate_csr_for_profile
from pkica.storage.revocations import add_revocation, is_revoked
from pkica.services.audit_service import log_event


SYSTEM_AVAILABLE = Path("/etc/nginx/sites-available/pkica-web.conf")
SYSTEM_ENABLED = Path("/etc/nginx/sites-enabled/pkica-web.conf")
WEB_CERT_PROFILE = "server_tls"
WEB_CERT_PURPOSE = "pkica-web"


class WebCertificateActionRequired(ValueError):
    def __init__(self, status: dict):
        self.status = status
        super().__init__(status["message"])


def ensure_intermediate_ready() -> None:
    if not ROOT_CERT_PATH.exists():
        raise ValueError("Root CA certificate not found.")
    if not INTERMEDIATE_KEY_PATH.exists() or not INTERMEDIATE_CERT_PATH.exists():
        raise ValueError("Intermediate CA is not initialized.")


def is_process_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def read_pid() -> int | None:
    if not WEB_PID_PATH.exists():
        return None
    try:
        return int(WEB_PID_PATH.read_text(encoding="utf-8").strip())
    except ValueError:
        return None


def public_key_bytes(key: object) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def web_cert_serial() -> str | None:
    if not WEB_CERT_PATH.exists():
        return None
    try:
        return format(load_certificate(WEB_CERT_PATH).serial_number, "x")
    except Exception:
        return None


def web_certificate_records() -> list[dict]:
    serial = web_cert_serial()
    records = load_issued_records(ISSUED_DB_PATH)
    return [
        record
        for record in records
        if record.get("purpose") == WEB_CERT_PURPOSE
        or Path(record.get("cert_path", "")) == WEB_CERT_PATH
        or (serial is not None and record.get("serial_number", "").lower() == serial)
    ]


def register_web_certificate(cert=None) -> dict | None:
    if not WEB_CERT_PATH.exists():
        return None

    cert = cert or load_certificate(WEB_CERT_PATH)
    serial = format(cert.serial_number, "x")
    existing = load_issued_records(ISSUED_DB_PATH)
    for record in existing:
        if record.get("serial_number", "").lower() == serial:
            record["purpose"] = WEB_CERT_PURPOSE
            record["cert_path"] = str(WEB_CERT_PATH)
            record["fullchain_path"] = str(WEB_FULLCHAIN_PATH)
            save_issued_records(ISSUED_DB_PATH, existing)
            return record

    record = certificate_to_record(cert, WEB_CERT_PROFILE, WEB_CERT_PATH, WEB_FULLCHAIN_PATH)
    record["purpose"] = WEB_CERT_PURPOSE
    append_issued_record(ISSUED_DB_PATH, record)
    log_event("web.cert.register", cert_path=str(WEB_CERT_PATH), serial_number=serial)
    return record


def certificate_has_host(cert, host: str) -> bool:
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        if host in san.get_values_for_type(x509.DNSName):
            return True
    except Exception:
        pass

    common_names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return bool(common_names and common_names[0].value == host)


def web_certificate_status(host: str) -> dict:
    status = {
        "key_exists": WEB_KEY_PATH.exists(),
        "cert_exists": WEB_CERT_PATH.exists(),
        "fullchain_exists": WEB_FULLCHAIN_PATH.exists(),
        "registered": False,
        "usable": False,
        "reasons": [],
        "message": "",
    }

    if not status["key_exists"] and not status["cert_exists"]:
        status["message"] = "Web key and certificate were not found."
        return status
    if not status["key_exists"]:
        status["reasons"].append("web private key is missing")
    if not status["cert_exists"]:
        status["reasons"].append("web certificate is missing")

    cert = None
    if status["cert_exists"]:
        try:
            cert = load_certificate(WEB_CERT_PATH)
            status["serial_number"] = format(cert.serial_number, "x")
        except Exception as exc:
            status["reasons"].append(f"web certificate cannot be loaded: {exc}")

    if status["key_exists"] and cert is not None:
        try:
            key = load_private_key(WEB_KEY_PATH)
            if public_key_bytes(key) != public_key_bytes(cert):
                status["reasons"].append("web private key does not match certificate")
        except Exception as exc:
            status["reasons"].append(f"web private key cannot be loaded: {exc}")

    if cert is not None:
        try:
            verify_certificate_chain(WEB_CERT_PATH, INTERMEDIATE_CERT_PATH, ROOT_CERT_PATH)
        except Exception as exc:
            status["reasons"].append(str(exc))
        if not certificate_has_host(cert, host):
            status["reasons"].append(f"web certificate is not valid for host {host}")
        if is_revoked(REVOKED_DB_PATH, format(cert.serial_number, "x")):
            status["reasons"].append("web certificate is revoked")

    records = web_certificate_records()
    status["registered"] = bool(records)
    if any(record.get("status") == "revoked" for record in records):
        status["reasons"].append("web certificate is revoked in issued DB")

    status["usable"] = bool(status["key_exists"] and cert is not None and not status["reasons"])
    status["message"] = "Existing web certificate can be reused." if status["usable"] else "; ".join(status["reasons"])
    return status


def revoke_web_certificates(reason: str = "superseded") -> None:
    for record in web_certificate_records():
        if record.get("status") == "revoked":
            continue
        serial = record["serial_number"]
        if not is_revoked(REVOKED_DB_PATH, serial):
            revocation = add_revocation(REVOKED_DB_PATH, serial, reason, record.get("cert_path", str(WEB_CERT_PATH)))
        else:
            revocation = {"revoked_at": record.get("revoked_at", "")}
        try:
            mark_issued_record_revoked(ISSUED_DB_PATH, serial, reason, revocation["revoked_at"])
        except ValueError:
            pass
        log_event("web.cert.revoke", serial_number=serial, reason=reason)


def remove_web_certificate_files(remove_key: bool = False) -> None:
    WEB_CERT_PATH.unlink(missing_ok=True)
    WEB_FULLCHAIN_PATH.unlink(missing_ok=True)
    WEB_CSR_PATH.unlink(missing_ok=True)
    if remove_key:
        WEB_KEY_PATH.unlink(missing_ok=True)


def generate_web_certificate(
    host: str,
    days: int = 365,
    intermediate_password: str | None = None,
    action: str = "auto",
) -> None:
    ensure_intermediate_ready()
    existing_status = web_certificate_status(host)
    if action == "auto":
        if existing_status["usable"]:
            if not existing_status["fullchain_exists"]:
                cert = load_certificate(WEB_CERT_PATH)
                save_fullchain(
                    cert,
                    load_certificate(INTERMEDIATE_CERT_PATH),
                    load_certificate(ROOT_CERT_PATH),
                    WEB_FULLCHAIN_PATH,
                )
            register_web_certificate()
            log_event("web.cert.reuse", cert_path=str(WEB_CERT_PATH), serial_number=existing_status.get("serial_number"))
            return
        if existing_status["key_exists"] or existing_status["cert_exists"]:
            raise WebCertificateActionRequired(existing_status)
    elif action == "reuse":
        if not existing_status["usable"]:
            raise ValueError(f"Existing web certificate cannot be reused: {existing_status['message']}")
        if not existing_status["fullchain_exists"]:
            cert = load_certificate(WEB_CERT_PATH)
            save_fullchain(
                cert,
                load_certificate(INTERMEDIATE_CERT_PATH),
                load_certificate(ROOT_CERT_PATH),
                WEB_FULLCHAIN_PATH,
            )
        register_web_certificate()
        log_event("web.cert.reuse", cert_path=str(WEB_CERT_PATH), serial_number=existing_status.get("serial_number"))
        return
    elif action == "rotate-cert":
        if existing_status.get("serial_number"):
            if not existing_status["registered"]:
                register_web_certificate()
            revoke_web_certificates()
        remove_web_certificate_files(remove_key=False)
    elif action == "rotate-key":
        if existing_status.get("serial_number"):
            if not existing_status["registered"]:
                register_web_certificate()
            revoke_web_certificates()
        remove_web_certificate_files(remove_key=True)
    else:
        raise ValueError(f"Unsupported web certificate action: {action}")

    intermediate_key = load_private_key(INTERMEDIATE_KEY_PATH, intermediate_password)
    intermediate_cert = load_certificate(INTERMEDIATE_CERT_PATH)
    root_cert = load_certificate(ROOT_CERT_PATH)
    WEB_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    WEB_CSR_PATH.parent.mkdir(parents=True, exist_ok=True)
    WEB_CERT_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not WEB_KEY_PATH.exists():
        key = generate_private_key("rsa", 2048)
        save_private_key(key, WEB_KEY_PATH)
        log_event("web.key.generate", key_path=str(WEB_KEY_PATH))
    else:
        key = load_private_key(WEB_KEY_PATH)

    csr = create_csr(key, common_name=host, organization="pkica web", country="RU", dns_names=[host])
    validate_csr_for_profile(csr, "server_tls")
    save_csr(csr, WEB_CSR_PATH)
    log_event("web.csr.generate", csr_path=str(WEB_CSR_PATH), host=host)

    cert = create_end_entity_certificate(
        intermediate_private_key=intermediate_key,
        intermediate_cert=intermediate_cert,
        csr=csr,
        days=days,
        extensions=build_end_entity_extensions(csr, "server_tls"),
    )
    save_certificate(cert, WEB_CERT_PATH)
    save_fullchain(cert, intermediate_cert, root_cert, WEB_FULLCHAIN_PATH)
    record = register_web_certificate(cert)
    log_event("web.cert.issue", cert_path=str(WEB_CERT_PATH), host=host, serial_number=format(cert.serial_number, "x"))
    if record:
        log_event("cert.issue", serial_number=record["serial_number"], profile=record["profile"], source="web")


def nginx_config_text(host: str, port: int) -> str:
    return f"""server {{
    listen 80;
    server_name {host};
    return 301 https://$host$request_uri;
}}

server {{
    listen 443 ssl;
    server_name {host};

    ssl_certificate {WEB_FULLCHAIN_PATH.resolve()};
    ssl_certificate_key {WEB_KEY_PATH.resolve()};

    location / {{
        proxy_pass http://127.0.0.1:{port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }}
}}
"""


def write_nginx_config(host: str, port: int) -> Path:
    WEB_NGINX_CONF_PATH.parent.mkdir(parents=True, exist_ok=True)
    WEB_NGINX_CONF_PATH.write_text(nginx_config_text(host, port), encoding="utf-8")
    log_event("web.nginx.generate", nginx_conf=str(WEB_NGINX_CONF_PATH), host=host, port=port)
    return WEB_NGINX_CONF_PATH


def configure_system_nginx() -> tuple[bool, str]:
    if shutil.which("nginx") is None:
        return False, "nginx not found"
    if not os.access(SYSTEM_AVAILABLE.parent, os.W_OK) or not os.access(SYSTEM_ENABLED.parent, os.W_OK):
        return False, "No write access to /etc/nginx sites directories"
    shutil.copy2(WEB_NGINX_CONF_PATH, SYSTEM_AVAILABLE)
    if SYSTEM_ENABLED.exists() or SYSTEM_ENABLED.is_symlink():
        SYSTEM_ENABLED.unlink()
    SYSTEM_ENABLED.symlink_to(SYSTEM_AVAILABLE)
    test = subprocess.run(["nginx", "-t"], text=True, capture_output=True, check=False)
    log_event("web.nginx.test", result="success" if test.returncode == 0 else "failed", output=(test.stdout + test.stderr)[-500:])
    if test.returncode != 0:
        return False, test.stdout + test.stderr
    reload_cmd = ["systemctl", "restart", "nginx"] if shutil.which("systemctl") else ["nginx", "-s", "reload"]
    reload_result = subprocess.run(reload_cmd, text=True, capture_output=True, check=False)
    log_event("web.nginx.reload", result="success" if reload_result.returncode == 0 else "failed")
    return reload_result.returncode == 0, reload_result.stdout + reload_result.stderr


def start_web(
    host: str = "pkica.local",
    port: int = 8000,
    configure_nginx: bool = False,
    intermediate_password: str | None = None,
    web_cert_action: str = "auto",
) -> dict:
    ensure_ca_directories()
    generate_web_certificate(host, intermediate_password=intermediate_password, action=web_cert_action)
    write_nginx_config(host, port)

    pid = read_pid()
    if pid and is_process_running(pid):
        running_pid = pid
    else:
        WEB_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        log_handle = WEB_LOG_PATH.open("ab")
        process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "pkica.web.app:app", "--host", "127.0.0.1", "--port", str(port)],
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        running_pid = process.pid
        WEB_PID_PATH.parent.mkdir(parents=True, exist_ok=True)
        WEB_PID_PATH.write_text(str(running_pid), encoding="utf-8")

    system_nginx = {"configured": False, "message": "not requested"}
    if configure_nginx:
        ok, message = configure_system_nginx()
        system_nginx = {"configured": ok, "message": message}

    WEB_STATE_PATH.write_text(
        json.dumps({"host": host, "port": port, "pid": running_pid, "system_nginx_configured": system_nginx["configured"]}, indent=2),
        encoding="utf-8",
    )
    log_event("web.start", host=host, port=port, pid=running_pid, configure_nginx=configure_nginx)
    return {"url": f"https://{host}/", "pid": running_pid, "nginx_conf": str(WEB_NGINX_CONF_PATH), "system_nginx": system_nginx}


def stop_web() -> dict:
    pid = read_pid()
    if not pid:
        return {"stopped": False, "message": "PID file not found"}
    if is_process_running(pid):
        os.kill(pid, signal.SIGTERM)
        stopped = True
    else:
        stopped = False
    WEB_PID_PATH.unlink(missing_ok=True)
    log_event("web.stop", pid=pid, stopped=stopped)
    return {"stopped": stopped, "pid": pid}


def web_status() -> dict:
    pid = read_pid()
    cert_info = None
    if WEB_CERT_PATH.exists():
        cert = load_certificate(WEB_CERT_PATH)
        cert_info = {"path": str(WEB_CERT_PATH), "not_valid_after": cert.not_valid_after_utc.isoformat()}
    state = {}
    if WEB_STATE_PATH.exists():
        state = json.loads(WEB_STATE_PATH.read_text(encoding="utf-8"))
    return {
        "certificate": cert_info,
        "pid": pid,
        "running": bool(pid and is_process_running(pid)),
        "nginx_conf": str(WEB_NGINX_CONF_PATH) if WEB_NGINX_CONF_PATH.exists() else "-",
        "system_nginx_configured": bool(state.get("system_nginx_configured")),
    }


def cleanup_web_artifacts() -> None:
    stop_web()
    state = {}
    if WEB_STATE_PATH.exists():
        state = json.loads(WEB_STATE_PATH.read_text(encoding="utf-8"))
    if state.get("system_nginx_configured"):
        if SYSTEM_ENABLED.is_symlink() and SYSTEM_ENABLED.resolve() == SYSTEM_AVAILABLE:
            SYSTEM_ENABLED.unlink(missing_ok=True)
        if SYSTEM_AVAILABLE.exists():
            SYSTEM_AVAILABLE.unlink(missing_ok=True)
    if BASE_DIR.joinpath("web").exists():
        shutil.rmtree(BASE_DIR / "web")
    log_event("web.cleanup", result="success")
