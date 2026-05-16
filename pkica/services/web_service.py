from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
from pathlib import Path

from pkica.config import (
    BASE_DIR,
    INTERMEDIATE_CERT_PATH,
    INTERMEDIATE_KEY_PATH,
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
from pkica.pki.ca import create_end_entity_certificate, load_certificate, save_certificate, save_fullchain
from pkica.pki.csr import create_csr, save_csr
from pkica.pki.keys import generate_private_key, load_private_key, save_private_key
from pkica.policy.profiles import build_end_entity_extensions, validate_csr_for_profile
from pkica.services.audit_service import log_event


SYSTEM_AVAILABLE = Path("/etc/nginx/sites-available/pkica-web.conf")
SYSTEM_ENABLED = Path("/etc/nginx/sites-enabled/pkica-web.conf")


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


def generate_web_certificate(
    host: str,
    days: int = 365,
    intermediate_password: str | None = None,
) -> None:
    ensure_intermediate_ready()
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
    log_event("web.cert.issue", cert_path=str(WEB_CERT_PATH), host=host, serial_number=format(cert.serial_number, "x"))


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
) -> dict:
    ensure_ca_directories()
    generate_web_certificate(host, intermediate_password=intermediate_password)
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
