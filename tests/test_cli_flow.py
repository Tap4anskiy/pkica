from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def run_pkica(cwd: Path, *args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        str(PROJECT_ROOT)
        if not pythonpath
        else os.pathsep.join([str(PROJECT_ROOT), pythonpath])
    )

    return subprocess.run(
        [sys.executable, "-m", "pkica.cli", *args],
        cwd=cwd,
        input=input_text,
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )


def assert_success(result: subprocess.CompletedProcess[str]) -> str:
    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    return output


def assert_failure(result: subprocess.CompletedProcess[str]) -> str:
    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    return output


def load_json(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_cli_ca_happy_path_from_clean_temp_directory(tmp_path: Path) -> None:
    output = assert_success(
        run_pkica(
            tmp_path,
            "ca",
            "init-root",
            "--algo",
            "rsa",
            "--rsa-bits",
            "2048",
            "--days",
            "3650",
            "--subject",
            "C=RU,O=Test CA,CN=Test Root CA",
        )
    )
    assert "Root CA cert saved to:" in output
    assert (tmp_path / "data/ca/root/private/root.key.pem").is_file()
    assert (tmp_path / "data/ca/root/certs/root.crt.pem").is_file()

    output = assert_success(
        run_pkica(
            tmp_path,
            "ca",
            "init-intermediate",
            "--algo",
            "rsa",
            "--rsa-bits",
            "2048",
            "--days",
            "1825",
            "--pathlen",
            "0",
            "--subject",
            "C=RU,O=Test CA,CN=Test Intermediate CA",
        )
    )
    assert "Intermediate CA cert saved to:" in output
    assert "Warning: isolate the Root CA private key" in output
    assert "restricted-access system or to a protected external storage device" in output
    assert (tmp_path / "data/ca/intermediate/private/intermediate.key.pem").is_file()
    assert (tmp_path / "data/ca/intermediate/certs/intermediate.crt.pem").is_file()

    output = assert_success(
        run_pkica(
            tmp_path,
            "key",
            "gen",
            "--name",
            "web-01",
            "--algo",
            "rsa",
            "--rsa-bits",
            "2048",
        )
    )
    assert "Private key saved to:" in output
    assert (tmp_path / "data/subjects/keys/web-01.key.pem").is_file()

    output = assert_success(
        run_pkica(
            tmp_path,
            "csr",
            "gen",
            "--name",
            "web-01",
            "--key",
            "data/subjects/keys/web-01.key.pem",
            "--cn",
            "web-01.lab",
            "--org",
            "Test CA",
            "--country",
            "RU",
            "--san-dns",
            "web-01.lab",
            "--san-ip",
            "192.168.56.10",
        )
    )
    assert "CSR saved to:" in output
    assert (tmp_path / "data/subjects/csrs/web-01.csr.pem").is_file()

    output = assert_success(
        run_pkica(
            tmp_path,
            "req",
            "submit",
            "--csr",
            "data/subjects/csrs/web-01.csr.pem",
            "--profile",
            "server_tls",
        )
    )
    assert "Request submitted successfully." in output
    assert "Request ID: 1" in output
    assert "Status:     pending" in output

    output = assert_success(run_pkica(tmp_path, "req", "approve", "--req-id", "1"))
    assert "Request approved successfully." in output
    assert "Status:     approved" in output

    output = assert_success(
        run_pkica(tmp_path, "cert", "issue", "--req-id", "1", "--days", "365")
    )
    assert "Certificate issued successfully." in output
    serial_match = re.search(r"^Serial:\s+([0-9a-f]+)$", output, re.MULTILINE)
    assert serial_match, output
    serial = serial_match.group(1)
    assert (tmp_path / f"data/issued/{serial}.crt.pem").is_file()
    assert (tmp_path / f"data/issued/{serial}.fullchain.pem").is_file()

    requests = load_json(tmp_path / "data/db/requests.json")
    assert requests[0]["status"] == "issued"
    assert requests[0]["issued_serial_number"] == serial

    issued = load_json(tmp_path / "data/db/issued.json")
    assert issued[0]["serial_number"] == serial
    assert issued[0]["status"] == "issued"
    assert issued[0]["profile"] == "server_tls"
    assert issued[0]["request_id"] == 1

    output = assert_success(run_pkica(tmp_path, "cert", "show", "--serial", serial))
    assert "Certificate information" in output
    assert f"Serial:        {serial}" in output
    assert "Status:        issued" in output
    assert "Profile:       server_tls" in output
    assert "Subject CN:    web-01.lab" in output
    assert "Basic constr.: CA:FALSE" in output
    assert "EKU:           serverAuth" in output
    assert "SAN:           DNS:web-01.lab, IP:192.168.56.10" in output

    output = assert_success(
        run_pkica(
            tmp_path,
            "cert",
            "revoke",
            "--serial",
            serial,
            "--reason",
            "keyCompromise",
        )
    )
    assert "Certificate revoked successfully." in output
    assert f"Serial:     {serial}" in output
    assert "Reason:     keyCompromise" in output

    output = assert_success(run_pkica(tmp_path, "crl", "publish", "--days", "7"))
    assert "CRL published successfully." in output
    assert "Revoked certs: 1" in output
    assert (tmp_path / "data/crl/intermediate.crl.pem").is_file()

    output = assert_success(run_pkica(tmp_path, "status"))
    assert "PKICA status" in output
    assert "Root CA:         ready" in output
    assert "Intermediate CA: ready" in output
    assert "CRL:             published" in output
    assert "Total:           1" in output
    assert "Issued:          1" in output
    assert "Total issued:    1" in output
    assert "Revoked:         1" in output
    assert "Revocation DB:   1" in output
    assert "Warning: Root CA private key is present in the local CA directory." in output
    assert "restricted-access system or to a protected external storage device" in output


def test_cli_reports_errors_for_invalid_operations(tmp_path: Path) -> None:
    output = assert_failure(run_pkica(tmp_path, "ca", "init-intermediate", "--subject", "CN=No Root"))
    assert "Root CA is not initialized." in output

    output = assert_failure(
        run_pkica(
            tmp_path,
            "req",
            "submit",
            "--csr",
            "missing.csr.pem",
            "--profile",
            "server_tls",
        )
    )
    assert "CSR not found: missing.csr.pem" in output

    assert_success(
        run_pkica(
            tmp_path,
            "ca",
            "init-root",
            "--algo",
            "rsa",
            "--rsa-bits",
            "2048",
            "--days",
            "3650",
            "--subject",
            "C=RU,O=Test CA,CN=Test Root CA",
        )
    )

    output = assert_failure(
        run_pkica(
            tmp_path,
            "ca",
            "init-root",
            "--algo",
            "rsa",
            "--rsa-bits",
            "2048",
            "--days",
            "3650",
            "--subject",
            "C=RU,O=Test CA,CN=Test Root CA",
        )
    )
    assert "Root CA already exists. Refusing to overwrite." in output
