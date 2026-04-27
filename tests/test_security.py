from __future__ import annotations

import os
import stat
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from pkica.pki.verify import verify_certificate_chain


def run_pkica(cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
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


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def init_ca(cwd: Path, *, intermediate_days: str = "30") -> None:
    assert_success(
        run_pkica(
            cwd,
            "ca",
            "init-root",
            "--algo",
            "rsa",
            "--rsa-bits",
            "2048",
            "--days",
            "365",
            "--subject",
            "C=RU,O=Security Test,CN=Security Root CA",
        )
    )
    assert_success(
        run_pkica(
            cwd,
            "ca",
            "init-intermediate",
            "--algo",
            "rsa",
            "--rsa-bits",
            "2048",
            "--days",
            intermediate_days,
            "--pathlen",
            "0",
            "--subject",
            "C=RU,O=Security Test,CN=Security Intermediate CA",
        )
    )


def issue_server_cert(cwd: Path, *, days: str = "7") -> str:
    assert_success(
        run_pkica(
            cwd,
            "key",
            "gen",
            "--name",
            "web",
            "--algo",
            "rsa",
            "--rsa-bits",
            "2048",
        )
    )
    assert_success(
        run_pkica(
            cwd,
            "csr",
            "gen",
            "--name",
            "web",
            "--key",
            "data/subjects/keys/web.key.pem",
            "--cn",
            "web.security.test",
            "--org",
            "Security Test",
            "--country",
            "RU",
            "--san-dns",
            "web.security.test",
        )
    )
    assert_success(
        run_pkica(
            cwd,
            "req",
            "submit",
            "--csr",
            "data/subjects/csrs/web.csr.pem",
            "--profile",
            "server_tls",
        )
    )
    assert_success(run_pkica(cwd, "req", "approve", "--req-id", "1"))
    output = assert_success(run_pkica(cwd, "cert", "issue", "--req-id", "1", "--days", days))

    for line in output.splitlines():
        if line.startswith("Serial:"):
            return line.split(":", 1)[1].strip()

    raise AssertionError(output)


def issue_client_cert(cwd: Path) -> str:
    assert_success(
        run_pkica(
            cwd,
            "key",
            "gen",
            "--name",
            "client",
            "--algo",
            "rsa",
            "--rsa-bits",
            "2048",
        )
    )
    assert_success(
        run_pkica(
            cwd,
            "csr",
            "gen",
            "--name",
            "client",
            "--key",
            "data/subjects/keys/client.key.pem",
            "--cn",
            "client.security.test",
            "--org",
            "Security Test",
            "--country",
            "RU",
        )
    )
    assert_success(
        run_pkica(
            cwd,
            "req",
            "submit",
            "--csr",
            "data/subjects/csrs/client.csr.pem",
            "--profile",
            "client_tls",
        )
    )
    assert_success(run_pkica(cwd, "req", "approve", "--req-id", "1"))
    output = assert_success(run_pkica(cwd, "cert", "issue", "--req-id", "1", "--days", "7"))

    for line in output.splitlines():
        if line.startswith("Serial:"):
            return line.split(":", 1)[1].strip()

    raise AssertionError(output)


def private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def save_cert(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def ca_cert(
    *,
    subject: x509.Name,
    issuer: x509.Name,
    public_key: rsa.RSAPublicKey,
    issuer_key: rsa.RSAPrivateKey,
    ca: bool = True,
) -> x509.Certificate:
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
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
        .sign(private_key=issuer_key, algorithm=hashes.SHA256())
    )


def leaf_cert(
    *,
    subject: x509.Name,
    issuer: x509.Name,
    public_key: rsa.RSAPublicKey,
    issuer_key: rsa.RSAPrivateKey,
    eku_oid: x509.ObjectIdentifier = ExtendedKeyUsageOID.SERVER_AUTH,
) -> x509.Certificate:
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([eku_oid]), critical=False)
        .sign(private_key=issuer_key, algorithm=hashes.SHA256())
    )


def write_chain(
    tmp_path: Path,
    *,
    root_cert: x509.Certificate,
    intermediate_cert: x509.Certificate,
    leaf_cert: x509.Certificate,
) -> tuple[Path, Path, Path]:
    root_path = tmp_path / "root.crt.pem"
    intermediate_path = tmp_path / "intermediate.crt.pem"
    leaf_path = tmp_path / "leaf.crt.pem"
    save_cert(root_path, root_cert)
    save_cert(intermediate_path, intermediate_cert)
    save_cert(leaf_path, leaf_cert)
    return leaf_path, intermediate_path, root_path


def test_ca_private_keys_and_sensitive_directories_are_private(tmp_path: Path) -> None:
    init_ca(tmp_path)

    assert mode(tmp_path / "data/ca/root/private/root.key.pem") == 0o600
    assert mode(tmp_path / "data/ca/intermediate/private/intermediate.key.pem") == 0o600

    for directory in [
        tmp_path / "data/ca/root/private",
        tmp_path / "data/ca/intermediate/private",
        tmp_path / "data/subjects/keys",
        tmp_path / "data/db",
        tmp_path / "data/audit",
    ]:
        assert mode(directory) == 0o700


def test_verify_uses_existing_crl_by_default_and_rejects_revoked_cert(tmp_path: Path) -> None:
    init_ca(tmp_path)
    serial = issue_server_cert(tmp_path)
    cert_path = f"data/issued/{serial}.crt.pem"

    assert_success(run_pkica(tmp_path, "cert", "revoke", "--serial", serial))
    assert_success(run_pkica(tmp_path, "crl", "publish"))

    output = assert_failure(run_pkica(tmp_path, "verify", "--cert", cert_path))
    assert "Certificate verification failed" in output
    assert "Certificate is revoked" in output

    output = assert_success(run_pkica(tmp_path, "verify", "--cert", cert_path, "--no-crl"))
    assert "Chain:       valid" in output
    assert "CRL:         not checked" in output


def test_active_certificate_verification_checks_published_crl_by_default(tmp_path: Path) -> None:
    init_ca(tmp_path)
    serial = issue_server_cert(tmp_path)

    assert_success(run_pkica(tmp_path, "crl", "publish"))

    output = assert_success(run_pkica(tmp_path, "verify", "--cert", f"data/issued/{serial}.crt.pem"))
    assert "Chain:       valid" in output
    assert "CRL:         checked" in output
    assert "Revocation:  not revoked" in output


def test_verify_rejects_conflicting_or_missing_crl_options(tmp_path: Path) -> None:
    init_ca(tmp_path)
    serial = issue_server_cert(tmp_path)
    cert_path = f"data/issued/{serial}.crt.pem"

    output = assert_failure(
        run_pkica(tmp_path, "verify", "--cert", cert_path, "--crl", "missing.crl.pem")
    )
    assert "CRL not found: missing.crl.pem" in output

    output = assert_failure(
        run_pkica(
            tmp_path,
            "verify",
            "--cert",
            cert_path,
            "--crl",
            "missing.crl.pem",
            "--no-crl",
        )
    )
    assert "Use either --crl or --no-crl, not both." in output


def test_cannot_issue_leaf_that_outlives_intermediate_ca(tmp_path: Path) -> None:
    init_ca(tmp_path, intermediate_days="1")

    assert_success(
        run_pkica(
            tmp_path,
            "key",
            "gen",
            "--name",
            "too-long",
            "--algo",
            "rsa",
            "--rsa-bits",
            "2048",
        )
    )
    assert_success(
        run_pkica(
            tmp_path,
            "csr",
            "gen",
            "--name",
            "too-long",
            "--key",
            "data/subjects/keys/too-long.key.pem",
            "--cn",
            "too-long.security.test",
            "--san-dns",
            "too-long.security.test",
        )
    )
    assert_success(
        run_pkica(
            tmp_path,
            "req",
            "submit",
            "--csr",
            "data/subjects/csrs/too-long.csr.pem",
            "--profile",
            "server_tls",
        )
    )
    assert_success(run_pkica(tmp_path, "req", "approve", "--req-id", "1"))

    output = assert_failure(run_pkica(tmp_path, "cert", "issue", "--req-id", "1", "--days", "30"))
    assert "End-entity certificate cannot outlive the intermediate certificate" in output


def test_request_state_machine_rejects_invalid_transitions(tmp_path: Path) -> None:
    init_ca(tmp_path)

    assert_success(
        run_pkica(
            tmp_path,
            "key",
            "gen",
            "--name",
            "state",
            "--algo",
            "rsa",
            "--rsa-bits",
            "2048",
        )
    )
    assert_success(
        run_pkica(
            tmp_path,
            "csr",
            "gen",
            "--name",
            "state",
            "--key",
            "data/subjects/keys/state.key.pem",
            "--cn",
            "state.security.test",
            "--san-dns",
            "state.security.test",
        )
    )
    assert_success(
        run_pkica(
            tmp_path,
            "req",
            "submit",
            "--csr",
            "data/subjects/csrs/state.csr.pem",
            "--profile",
            "server_tls",
        )
    )

    output = assert_failure(run_pkica(tmp_path, "cert", "issue", "--req-id", "1"))
    assert "Request must be approved before issuing. Current status: pending" in output

    assert_success(run_pkica(tmp_path, "req", "approve", "--req-id", "1"))
    assert_success(run_pkica(tmp_path, "cert", "issue", "--req-id", "1", "--days", "7"))

    output = assert_failure(run_pkica(tmp_path, "req", "approve", "--req-id", "1"))
    assert "Only pending requests can be approved. Current status: issued" in output

    output = assert_failure(
        run_pkica(tmp_path, "req", "reject", "--req-id", "1", "--reason", "too late")
    )
    assert "Only pending or approved requests can be rejected. Current status: issued" in output


def test_revoke_and_show_reject_missing_or_repeated_targets(tmp_path: Path) -> None:
    init_ca(tmp_path)
    serial = issue_server_cert(tmp_path)

    output = assert_failure(run_pkica(tmp_path, "cert", "show", "--serial", "deadbeef"))
    assert "Certificate not found by serial: deadbeef" in output

    assert_success(run_pkica(tmp_path, "cert", "revoke", "--serial", serial))
    output = assert_failure(run_pkica(tmp_path, "cert", "revoke", "--serial", serial))
    assert f"Certificate already revoked: {serial}" in output


def test_server_tls_profile_requires_san_at_issue_time(tmp_path: Path) -> None:
    init_ca(tmp_path)

    assert_success(
        run_pkica(
            tmp_path,
            "key",
            "gen",
            "--name",
            "no-san",
            "--algo",
            "rsa",
            "--rsa-bits",
            "2048",
        )
    )
    assert_success(
        run_pkica(
            tmp_path,
            "csr",
            "gen",
            "--name",
            "no-san",
            "--key",
            "data/subjects/keys/no-san.key.pem",
            "--cn",
            "no-san.security.test",
        )
    )
    assert_success(
        run_pkica(
            tmp_path,
            "req",
            "submit",
            "--csr",
            "data/subjects/csrs/no-san.csr.pem",
            "--profile",
            "server_tls",
        )
    )
    assert_success(run_pkica(tmp_path, "req", "approve", "--req-id", "1"))

    output = assert_failure(run_pkica(tmp_path, "cert", "issue", "--req-id", "1"))
    assert "server_tls profile requires Subject Alternative Name" in output


def test_client_tls_certificate_uses_client_auth_eku(tmp_path: Path) -> None:
    init_ca(tmp_path)
    serial = issue_client_cert(tmp_path)

    output = assert_success(run_pkica(tmp_path, "cert", "show", "--serial", serial))
    assert "Profile:       client_tls" in output
    assert "Subject CN:    client.security.test" in output
    assert "EKU:           clientAuth" in output
    assert "SAN:           -" in output

    output = assert_success(run_pkica(tmp_path, "verify", "--cert", f"data/issued/{serial}.crt.pem", "--no-crl"))
    assert "Chain:       valid" in output


def test_verify_rejects_intermediate_without_ca_true(tmp_path: Path) -> None:
    root_key = private_key()
    intermediate_key = private_key()
    leaf_key = private_key()

    root_subject = name("Root CA")
    intermediate_subject = name("Not Really CA")
    root_cert = ca_cert(
        subject=root_subject,
        issuer=root_subject,
        public_key=root_key.public_key(),
        issuer_key=root_key,
    )
    intermediate_cert = ca_cert(
        subject=intermediate_subject,
        issuer=root_subject,
        public_key=intermediate_key.public_key(),
        issuer_key=root_key,
        ca=False,
    )
    leaf = leaf_cert(
        subject=name("leaf"),
        issuer=intermediate_subject,
        public_key=leaf_key.public_key(),
        issuer_key=intermediate_key,
    )
    paths = write_chain(
        tmp_path,
        root_cert=root_cert,
        intermediate_cert=intermediate_cert,
        leaf_cert=leaf,
    )

    with pytest.raises(ValueError, match="Intermediate certificate must have CA:TRUE"):
        verify_certificate_chain(*paths)


def test_verify_rejects_leaf_with_wrong_eku(tmp_path: Path) -> None:
    root_key = private_key()
    intermediate_key = private_key()
    leaf_key = private_key()

    root_subject = name("Root CA")
    intermediate_subject = name("Intermediate CA")
    root_cert = ca_cert(
        subject=root_subject,
        issuer=root_subject,
        public_key=root_key.public_key(),
        issuer_key=root_key,
    )
    intermediate_cert = ca_cert(
        subject=intermediate_subject,
        issuer=root_subject,
        public_key=intermediate_key.public_key(),
        issuer_key=root_key,
    )
    leaf = leaf_cert(
        subject=name("leaf"),
        issuer=intermediate_subject,
        public_key=leaf_key.public_key(),
        issuer_key=intermediate_key,
        eku_oid=ExtendedKeyUsageOID.CODE_SIGNING,
    )
    paths = write_chain(
        tmp_path,
        root_cert=root_cert,
        intermediate_cert=intermediate_cert,
        leaf_cert=leaf,
    )

    with pytest.raises(ValueError, match="serverAuth or clientAuth"):
        verify_certificate_chain(*paths)


def test_verify_rejects_wrong_issuer_subject_chain(tmp_path: Path) -> None:
    root_key = private_key()
    intermediate_key = private_key()
    other_intermediate_key = private_key()
    leaf_key = private_key()

    root_subject = name("Root CA")
    intermediate_subject = name("Intermediate CA")
    other_intermediate_subject = name("Other Intermediate CA")
    root_cert = ca_cert(
        subject=root_subject,
        issuer=root_subject,
        public_key=root_key.public_key(),
        issuer_key=root_key,
    )
    intermediate_cert = ca_cert(
        subject=intermediate_subject,
        issuer=root_subject,
        public_key=intermediate_key.public_key(),
        issuer_key=root_key,
    )
    other_intermediate_cert = ca_cert(
        subject=other_intermediate_subject,
        issuer=root_subject,
        public_key=other_intermediate_key.public_key(),
        issuer_key=root_key,
    )
    leaf = leaf_cert(
        subject=name("leaf"),
        issuer=intermediate_subject,
        public_key=leaf_key.public_key(),
        issuer_key=intermediate_key,
    )
    paths = write_chain(
        tmp_path,
        root_cert=root_cert,
        intermediate_cert=other_intermediate_cert,
        leaf_cert=leaf,
    )

    with pytest.raises(ValueError, match="Certificate issuer does not match"):
        verify_certificate_chain(*paths)
