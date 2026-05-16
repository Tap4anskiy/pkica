from __future__ import annotations

import argparse
import getpass
import sys
import shutil

from pathlib import Path

from pkica.config import (
    BASE_DIR,
    AUDIT_LOG_PATH,
    INTERMEDIATE_CERT_PATH,
    INTERMEDIATE_CSR_PATH,
    INTERMEDIATE_KEY_PATH,
    ISSUED_DB_PATH,
    ISSUED_DIR,
    ROOT_CERT_PATH,
    ROOT_KEY_PATH,
    USER_CSR_DIR,
    USER_KEYS_DIR,
    REQUESTS_DB_PATH,
    REQUESTS_DIR,
    CRL_PATH,
    REVOKED_DB_PATH,
    NGINX_EXPORT_DIR,
    TRUST_EXPORT_DIR,
    ensure_ca_directories,
)
from pkica.pki.ca import (
    append_issued_record,
    certificate_to_record,
    create_end_entity_certificate,
    create_intermediate_ca_certificate,
    create_intermediate_csr,
    create_root_ca_certificate,
    load_issued_records,
    load_certificate,
    parse_subject,
    save_certificate,
    save_csr,
    save_fullchain,
    find_issued_record_by_request_id,
    find_issued_record_by_serial,
    mark_issued_record_revoked
)
from pkica.storage.requests import (
    find_request,
    load_requests,
    mark_request_issued,
    submit_request,
    update_request_status,
)
from pkica.pki.inspect import (
    get_basic_constraints_text,
    get_cn,
    get_eku_text,
    get_key_usage_text,
    get_san_text,
)
from pkica.policy.profiles import build_end_entity_extensions, validate_csr_for_profile
from pkica.storage.audit import append_jsonl
from pkica.pki.keys import generate_private_key, load_private_key, save_private_key
from pkica.pki.csr import create_csr, load_csr, save_csr as save_subject_csr
from pkica.pki.crl import REASON_MAP, create_crl, save_crl
from pkica.storage.revocations import add_revocation, load_revocations
from pkica.storage.status import count_by_status, load_json_list
from pkica.pki.verify import verify_certificate_chain
from pkica.storage.export import copy_file, write_chain
from pkica.services.web_service import cleanup_web_artifacts, start_web, stop_web, web_status

"""Создание корневого УЦ"""
def command_init_root(args: argparse.Namespace) -> int:
    ensure_ca_directories()

    if ROOT_KEY_PATH.exists() or ROOT_CERT_PATH.exists():
        print("Root CA already exists. Refusing to overwrite.")
        return 1

    password = None
    if args.encrypt:
        password = getpass.getpass("Enter password for Root CA private key: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Passwords do not match.")
            return 1
    else:
        print("Warning: Root CA private key will be stored without encryption.")

    subject = parse_subject(args.subject)
    private_key = generate_private_key(args.algo, args.rsa_bits)
    cert = create_root_ca_certificate(private_key, subject, args.days)

    save_private_key(private_key, ROOT_KEY_PATH, password=password)
    save_certificate(cert, ROOT_CERT_PATH)

    append_jsonl(
        AUDIT_LOG_PATH,
        {
            "action": "ca.init_root",
            "subject": args.subject,
            "algorithm": args.algo,
            "rsa_bits": args.rsa_bits,
            "days": args.days,
            "encrypted": args.encrypt,
            "key_path": str(ROOT_KEY_PATH),
            "cert_path": str(ROOT_CERT_PATH),
        },
    )

    print(f"Root CA key saved to:  {ROOT_KEY_PATH}")
    print(f"Root CA cert saved to: {ROOT_CERT_PATH}")
    return 0


"""Создание промежуточного УЦ"""
def command_init_intermediate(args: argparse.Namespace) -> int:
    ensure_ca_directories()

    if not ROOT_KEY_PATH.exists() or not ROOT_CERT_PATH.exists():
        print("Root CA is not initialized.")
        return 1

    if INTERMEDIATE_KEY_PATH.exists() or INTERMEDIATE_CERT_PATH.exists():
        print("Intermediate CA already exists. Refusing to overwrite.")
        return 1

    root_password = None
    if args.root_key_encrypted:
        root_password = getpass.getpass("Enter password for Root CA private key: ")

    intermediate_password = None
    if args.encrypt:
        intermediate_password = getpass.getpass("Enter password for Intermediate CA private key: ")
        confirm = getpass.getpass("Confirm password: ")
        if intermediate_password != confirm:
            print("Passwords do not match.")
            return 1
    else:
        print("Warning: Intermediate CA private key will be stored without encryption.")

    root_key = load_private_key(ROOT_KEY_PATH, root_password)
    root_cert = load_certificate(ROOT_CERT_PATH)

    subject = parse_subject(args.subject)
    intermediate_key = generate_private_key(args.algo, args.rsa_bits)
    intermediate_csr = create_intermediate_csr(intermediate_key, subject)
    intermediate_cert = create_intermediate_ca_certificate(
        root_private_key=root_key,
        root_cert=root_cert,
        intermediate_csr=intermediate_csr,
        days=args.days,
        pathlen=args.pathlen,
    )

    save_private_key(intermediate_key, INTERMEDIATE_KEY_PATH, password=intermediate_password)
    save_csr(intermediate_csr, INTERMEDIATE_CSR_PATH)
    save_certificate(intermediate_cert, INTERMEDIATE_CERT_PATH)

    append_jsonl(
        AUDIT_LOG_PATH,
        {
            "action": "ca.init_intermediate",
            "subject": args.subject,
            "algorithm": args.algo,
            "rsa_bits": args.rsa_bits,
            "days": args.days,
            "pathlen": args.pathlen,
            "encrypted": args.encrypt,
            "root_key_encrypted": args.root_key_encrypted,
            "key_path": str(INTERMEDIATE_KEY_PATH),
            "csr_path": str(INTERMEDIATE_CSR_PATH),
            "cert_path": str(INTERMEDIATE_CERT_PATH),
        },
    )

    print(f"Intermediate CA key saved to:  {INTERMEDIATE_KEY_PATH}")
    print(f"Intermediate CA CSR saved to:  {INTERMEDIATE_CSR_PATH}")
    print(f"Intermediate CA cert saved to: {INTERMEDIATE_CERT_PATH}")
    print(
        "Warning: isolate the Root CA private key by moving it to a restricted-access "
        "system or to a protected external storage device."
    )
    return 0

def command_key_gen(args: argparse.Namespace) -> int:
    ensure_ca_directories()

    output_path = Path(args.out) if args.out else USER_KEYS_DIR / f"{args.name}.key.pem"

    if output_path.exists():
        print(f"Key already exists: {output_path}")
        return 1

    password = None
    if args.encrypt:
        password = getpass.getpass("Enter password for private key: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Passwords do not match.")
            return 1

    private_key = generate_private_key(args.algo, args.rsa_bits)
    save_private_key(private_key, output_path, password=password)

    append_jsonl(
        AUDIT_LOG_PATH,
        {
            "action": "key.gen",
            "name": args.name,
            "algorithm": args.algo,
            "rsa_bits": args.rsa_bits,
            "encrypted": args.encrypt,
            "key_path": str(output_path),
        },
    )

    print(f"Private key saved to: {output_path}")
    return 0

def command_csr_gen(args: argparse.Namespace) -> int:
    ensure_ca_directories()

    key_path = Path(args.key)
    if not key_path.exists():
        print(f"Private key not found: {key_path}")
        return 1

    output_path = Path(args.out) if args.out else USER_CSR_DIR / f"{args.name}.csr.pem"

    if output_path.exists():
        print(f"CSR already exists: {output_path}")
        return 1

    password = None
    if args.key_encrypted:
        password = getpass.getpass("Enter password for private key: ")

    private_key = load_private_key(key_path, password)

    csr = create_csr(
        private_key=private_key,
        common_name=args.cn,
        organization=args.org,
        country=args.country,
        dns_names=args.san_dns,
        ip_addresses=args.san_ip,
    )

    save_subject_csr(csr, output_path)

    append_jsonl(
        AUDIT_LOG_PATH,
        {
            "action": "csr.gen",
            "name": args.name,
            "key_path": str(key_path),
            "csr_path": str(output_path),
            "common_name": args.cn,
            "organization": args.org,
            "country": args.country,
            "san_dns": args.san_dns,
            "san_ip": args.san_ip,
        },
    )

    print(f"CSR saved to: {output_path}")
    return 0

def command_cert_issue(args: argparse.Namespace) -> int:
    ensure_ca_directories()

    if not args.csr and not args.req_id:
        print("Either --csr or --req-id must be provided.")
        return 1

    if args.csr and args.req_id:
        print("Use either --csr or --req-id, not both.")
        return 1

    request_id = None

    if args.req_id:
        requests = load_requests(REQUESTS_DB_PATH)
        request = find_request(requests, args.req_id)

        if request["status"] != "approved":
            print(f"Request must be approved before issuing. Current status: {request['status']}")
            return 1

        csr_path = Path(request["stored_csr_path"])
        profile = request["profile"]
        request_id = request["id"]

    else:
        if not args.profile:
            print("--profile is required when issuing directly from --csr.")
            return 1

        csr_path = Path(args.csr)
        profile = args.profile

    if not csr_path.exists():
        print(f"CSR not found: {csr_path}")
        return 1

    if not INTERMEDIATE_KEY_PATH.exists() or not INTERMEDIATE_CERT_PATH.exists():
        print("Intermediate CA is not initialized.")
        return 1

    if not ROOT_CERT_PATH.exists():
        print("Root CA certificate not found.")
        return 1

    intermediate_password = None
    if args.intermediate_key_encrypted:
        intermediate_password = getpass.getpass("Enter password for Intermediate CA private key: ")

    try:
        csr = load_csr(csr_path)
        validate_csr_for_profile(csr, profile)

        intermediate_key = load_private_key(INTERMEDIATE_KEY_PATH, intermediate_password)
        intermediate_cert = load_certificate(INTERMEDIATE_CERT_PATH)
        root_cert = load_certificate(ROOT_CERT_PATH)

        extensions = build_end_entity_extensions(csr, profile)

        cert = create_end_entity_certificate(
            intermediate_private_key=intermediate_key,
            intermediate_cert=intermediate_cert,
            csr=csr,
            days=args.days,
            extensions=extensions,
        )

        serial_hex = format(cert.serial_number, "x")
        cert_path = ISSUED_DIR / f"{serial_hex}.crt.pem"
        fullchain_path = ISSUED_DIR / f"{serial_hex}.fullchain.pem"

        if cert_path.exists() or fullchain_path.exists():
            print("Certificate file already exists. Refusing to overwrite.")
            return 1

        save_certificate(cert, cert_path)
        save_fullchain(cert, intermediate_cert, root_cert, fullchain_path)

        record = certificate_to_record(
            cert=cert,
            profile=profile,
            cert_path=cert_path,
            fullchain_path=fullchain_path,
        )

        if request_id is not None:
            record["request_id"] = request_id

        append_issued_record(ISSUED_DB_PATH, record)

        if request_id is not None:
            mark_request_issued(
                db_path=REQUESTS_DB_PATH,
                request_id=request_id,
                serial_number=serial_hex,
            )

        append_jsonl(
            AUDIT_LOG_PATH,
            {
                "action": "cert.issue",
                "request_id": request_id,
                "serial_number": serial_hex,
                "profile": profile,
                "csr_path": str(csr_path),
                "cert_path": str(cert_path),
            },
        )

        print("Certificate issued successfully.")
        print(f"Serial:     {serial_hex}")
        print(f"Profile:    {profile}")

        if request_id is not None:
            print(f"Request ID: {request_id}")

        print(f"Cert:       {cert_path}")
        print(f"Full chain: {fullchain_path}")
        return 0

    except Exception as exc:
        print(f"Error: {exc}")
        return 1

def command_req_submit(args: argparse.Namespace) -> int:
    ensure_ca_directories()

    csr_path = Path(args.csr)
    if not csr_path.exists():
        print(f"CSR not found: {csr_path}")
        return 1

    try:
        record = submit_request(
            db_path=REQUESTS_DB_PATH,
            csr_path=csr_path,
            requests_dir=REQUESTS_DIR,
            profile=args.profile,
        )

        append_jsonl(
            AUDIT_LOG_PATH,
            {
                "action": "req.submit",
                "request_id": record["id"],
                "profile": record["profile"],
                "csr_path": str(csr_path),
            },
        )

        print("Request submitted successfully.")
        print(f"Request ID: {record['id']}")
        print(f"Status:     {record['status']}")
        print(f"Profile:    {record['profile']}")
        print(f"CN:         {record['cn']}")
        print(f"Stored CSR: {record['stored_csr_path']}")
        return 0

    except Exception as exc:
        print(f"Error: {exc}")
        return 1


def command_req_list(args: argparse.Namespace) -> int:
    records = load_requests(REQUESTS_DB_PATH)

    if args.status:
        records = [record for record in records if record["status"] == args.status]

    if not records:
        print("No requests found.")
        return 0

    print(f"{'ID':<6} {'STATUS':<10} {'PROFILE':<12} {'CN':<25} {'CREATED'}")
    print("-" * 80)

    for record in records:
        cn = record.get("cn") or "-"
        print(
            f"{record['id']:<6} "
            f"{record['status']:<10} "
            f"{record['profile']:<12} "
            f"{cn:<25} "
            f"{record['created_at']}"
        )

    return 0


def command_req_approve(args: argparse.Namespace) -> int:
    try:
        record = update_request_status(
            db_path=REQUESTS_DB_PATH,
            request_id=args.req_id,
            status="approved",
        )

        append_jsonl(
            AUDIT_LOG_PATH,
            {
                "action": "req.approve",
                "request_id": record["id"],
                "profile": record["profile"],
            },
        )

        print("Request approved successfully.")
        print(f"Request ID: {record['id']}")
        print(f"Status:     {record['status']}")
        return 0

    except Exception as exc:
        print(f"Error: {exc}")
        return 1


def command_req_reject(args: argparse.Namespace) -> int:
    try:
        record = update_request_status(
            db_path=REQUESTS_DB_PATH,
            request_id=args.req_id,
            status="rejected",
            reason=args.reason,
        )

        append_jsonl(
            AUDIT_LOG_PATH,
            {
                "action": "req.reject",
                "request_id": record["id"],
                "profile": record["profile"],
                "reason": args.reason,
            },
        )

        print("Request rejected successfully.")
        print(f"Request ID: {record['id']}")
        print(f"Status:     {record['status']}")
        print(f"Reason:     {record['rejection_reason']}")
        return 0

    except Exception as exc:
        print(f"Error: {exc}")
        return 1

def command_cert_show(args: argparse.Namespace) -> int:
    if not args.serial and not args.req_id:
        print("Either --serial or --req-id must be provided.")
        return 1

    if args.serial and args.req_id:
        print("Use either --serial or --req-id, not both.")
        return 1

    try:
        if args.serial:
            record = find_issued_record_by_serial(
                db_path=ISSUED_DB_PATH,
                serial_number=args.serial,
            )
        else:
            record = find_issued_record_by_request_id(
                db_path=ISSUED_DB_PATH,
                request_id=args.req_id,
            )

        cert_path = Path(record["cert_path"])
        if not cert_path.exists():
            print(f"Certificate file not found: {cert_path}")
            return 1

        cert = load_certificate(cert_path)

        print("Certificate information")
        print("-" * 60)
        print(f"Serial:        {format(cert.serial_number, 'x')}")
        print(f"Status:        {record.get('status', '-')}")
        print(f"Profile:       {record.get('profile', '-')}")
        print(f"Request ID:    {record.get('request_id', '-')}")
        print(f"Subject:       {cert.subject.rfc4514_string()}")
        print(f"Subject CN:    {get_cn(cert.subject) or '-'}")
        print(f"Issuer:        {cert.issuer.rfc4514_string()}")
        print(f"Issuer CN:     {get_cn(cert.issuer) or '-'}")
        print(f"Valid from:    {cert.not_valid_before_utc.isoformat()}")
        print(f"Valid until:   {cert.not_valid_after_utc.isoformat()}")
        print(f"Basic constr.: {get_basic_constraints_text(cert)}")
        print(f"Key Usage:     {get_key_usage_text(cert)}")
        print(f"EKU:           {get_eku_text(cert)}")
        print(f"SAN:           {get_san_text(cert)}")
        print(f"Cert path:     {record.get('cert_path', '-')}")
        print(f"Fullchain:     {record.get('fullchain_path', '-')}")
        return 0

    except Exception as exc:
        print(f"Error: {exc}")
        return 1

def command_cert_revoke(args: argparse.Namespace) -> int:
    try:
        record = find_issued_record_by_serial(
            db_path=ISSUED_DB_PATH,
            serial_number=args.serial,
        )

        if record.get("status") == "revoked":
            print(f"Certificate already revoked: {args.serial}")
            return 1

        revocation = add_revocation(
            db_path=REVOKED_DB_PATH,
            serial_number=record["serial_number"],
            reason=args.reason,
            cert_path=record["cert_path"],
        )

        updated_record = mark_issued_record_revoked(
            db_path=ISSUED_DB_PATH,
            serial_number=record["serial_number"],
            reason=args.reason,
            revoked_at=revocation["revoked_at"],
        )

        append_jsonl(
            AUDIT_LOG_PATH,
            {
                "action": "cert.revoke",
                "serial_number": updated_record["serial_number"],
                "reason": args.reason,
                "cert_path": updated_record["cert_path"],
            },
        )

        print("Certificate revoked successfully.")
        print(f"Serial:     {updated_record['serial_number']}")
        print(f"Reason:     {args.reason}")
        print(f"Revoked at: {updated_record['revoked_at']}")
        return 0

    except Exception as exc:
        print(f"Error: {exc}")
        return 1

def command_crl_publish(args: argparse.Namespace) -> int:
    if not INTERMEDIATE_KEY_PATH.exists() or not INTERMEDIATE_CERT_PATH.exists():
        print("Intermediate CA is not initialized.")
        return 1

    intermediate_password = None
    if args.intermediate_key_encrypted:
        intermediate_password = getpass.getpass("Enter password for Intermediate CA private key: ")

    try:
        intermediate_key = load_private_key(INTERMEDIATE_KEY_PATH, intermediate_password)
        intermediate_cert = load_certificate(INTERMEDIATE_CERT_PATH)
        revoked_records = load_revocations(REVOKED_DB_PATH)

        crl = create_crl(
            issuer_cert=intermediate_cert,
            issuer_private_key=intermediate_key,
            revoked_records=revoked_records,
            days=args.days,
        )

        save_crl(crl, CRL_PATH)

        append_jsonl(
            AUDIT_LOG_PATH,
            {
                "action": "crl.publish",
                "crl_path": str(CRL_PATH),
                "revoked_count": len(revoked_records),
                "next_update_days": args.days,
            },
        )

        print("CRL published successfully.")
        print(f"CRL path:      {CRL_PATH}")
        print(f"Revoked certs: {len(revoked_records)}")
        return 0

    except Exception as exc:
        print(f"Error: {exc}")
        return 1

def command_verify(args: argparse.Namespace) -> int:
    cert_path = Path(args.cert)

    if not cert_path.exists():
        print(f"Certificate not found: {cert_path}")
        return 1

    if args.crl and args.no_crl:
        print("Use either --crl or --no-crl, not both.")
        return 1

    crl_path = None
    if args.no_crl:
        crl_path = None
    elif args.crl:
        crl_path = Path(args.crl)
    elif CRL_PATH.exists():
        crl_path = CRL_PATH

    if crl_path is not None and not crl_path.exists():
        print(f"CRL not found: {crl_path}")
        return 1

    try:
        result = verify_certificate_chain(
            cert_path=cert_path,
            intermediate_cert_path=INTERMEDIATE_CERT_PATH,
            root_cert_path=ROOT_CERT_PATH,
            crl_path=crl_path,
        )

        print("Certificate verification")
        print("-" * 60)
        print(f"Serial:      {result['serial_number']}")
        print(f"Subject:     {result['subject']}")
        print(f"Issuer:      {result['issuer']}")
        print("Chain:       valid")
        print(f"Trust chain: {result['trust_chain']}")

        if result["crl_checked"]:
            print("CRL:         checked")
            print("Revocation:  not revoked")
        else:
            print("CRL:         not checked")
            print("Warning:     revocation status was not checked")

        append_jsonl(
            AUDIT_LOG_PATH,
            {
                "action": "verify",
                "result": "success",
                "cert_path": str(cert_path),
                "crl_path": str(crl_path) if crl_path else None,
                "serial_number": result["serial_number"],
                "subject": result["subject"],
                "issuer": result["issuer"],
                "trust_chain": result["trust_chain"],
                "crl_checked": result["crl_checked"],
            },
        )

        return 0

    except Exception as exc:
        print("Certificate verification failed")
        print("-" * 60)
        print(f"Reason: {exc}")
        append_jsonl(
            AUDIT_LOG_PATH,
            {
                "action": "verify",
                "result": "failed",
                "cert_path": str(cert_path),
                "crl_path": str(crl_path) if crl_path else None,
                "reason": str(exc),
            },
        )
        return 1

def command_reset(args: argparse.Namespace) -> int:
    base_dir = BASE_DIR

    if not base_dir.exists():
        print("Nothing to reset. Data directory does not exist.")
        return 0

    if not args.force:
        confirm = input(
            "This will DELETE all PKI data (keys, certs, DB, CRL).\n"
            "Type 'yes' to continue: "
        )
        if confirm.strip().lower() != "yes":
            print("Aborted.")
            return 1

    try:
        cleanup_web_artifacts()
        shutil.rmtree(base_dir)
        print(f"Removed: {base_dir}")

        # пересоздаём базовую структуру (чтобы не было пусто)
        ensure_ca_directories()

        append_jsonl(
            AUDIT_LOG_PATH,
            {
                "action": "reset",
                "data_dir": str(base_dir),
                "force": args.force,
            },
        )

        print("PKI environment reset successfully.")
        return 0

    except Exception as exc:
        print(f"Error: {exc}")
        return 1

def command_status(args: argparse.Namespace) -> int:
    requests = load_json_list(REQUESTS_DB_PATH)
    issued = load_json_list(ISSUED_DB_PATH)
    revoked = load_json_list(REVOKED_DB_PATH)

    request_stats = count_by_status(requests)
    cert_stats = count_by_status(issued)

    root_ready = ROOT_CERT_PATH.exists()
    root_key_present = ROOT_KEY_PATH.exists()
    intermediate_ready = INTERMEDIATE_KEY_PATH.exists() and INTERMEDIATE_CERT_PATH.exists()
    crl_ready = CRL_PATH.exists()

    print("PKICA status")
    print("-" * 60)

    print("CA initialization")
    print(f"Root CA:         {'ready' if root_ready else 'not initialized'}")
    print(f"Intermediate CA: {'ready' if intermediate_ready else 'not initialized'}")
    print(f"CRL:             {'published' if crl_ready else 'not published'}")

    print()
    print("Requests")
    print(f"Total:           {len(requests)}")
    print(f"Pending:         {request_stats.get('pending', 0)}")
    print(f"Approved:        {request_stats.get('approved', 0)}")
    print(f"Issued:          {request_stats.get('issued', 0)}")
    print(f"Rejected:        {request_stats.get('rejected', 0)}")

    print()
    print("Certificates")
    print(f"Total issued:    {len(issued)}")
    print(f"Active:          {cert_stats.get('issued', 0)}")
    print(f"Revoked:         {cert_stats.get('revoked', 0)}")
    print(f"Revocation DB:   {len(revoked)}")

    print()
    print("Paths")
    print(f"Data dir:        {BASE_DIR}")
    print(f"Root cert:       {ROOT_CERT_PATH if ROOT_CERT_PATH.exists() else '-'}")
    print(f"Intermediate:    {INTERMEDIATE_CERT_PATH if INTERMEDIATE_CERT_PATH.exists() else '-'}")
    print(f"Requests DB:     {REQUESTS_DB_PATH if REQUESTS_DB_PATH.exists() else '-'}")
    print(f"Issued DB:       {ISSUED_DB_PATH if ISSUED_DB_PATH.exists() else '-'}")
    print(f"Revoked DB:      {REVOKED_DB_PATH if REVOKED_DB_PATH.exists() else '-'}")
    print(f"CRL path:        {CRL_PATH if CRL_PATH.exists() else '-'}")

    if root_key_present:
        print()
        print(
            "Warning: Root CA private key is present in the local CA directory. "
            "Isolate it by moving it to a restricted-access system or to a "
            "protected external storage device."
        )

    append_jsonl(
        AUDIT_LOG_PATH,
        {
            "action": "status",
            "root_ready": root_ready,
            "root_key_present": root_key_present,
            "intermediate_ready": intermediate_ready,
            "crl_ready": crl_ready,
            "requests_total": len(requests),
            "certificates_total": len(issued),
            "revocations_total": len(revoked),
        },
    )

    return 0


def command_web_start(args: argparse.Namespace) -> int:
    intermediate_password = None
    if args.intermediate_key_encrypted:
        intermediate_password = getpass.getpass("Enter password for Intermediate CA private key: ")

    try:
        result = start_web(
            host=args.host,
            port=args.port,
            configure_nginx=args.configure_nginx,
            intermediate_password=intermediate_password,
        )
        print("pkica web started.")
        print(f"URL:          {result['url']}")
        print(f"PID:          {result['pid']}")
        print(f"Nginx config: {result['nginx_conf']}")
        if not args.configure_nginx:
            print()
            print("Manual nginx setup:")
            print(f"sudo cp {result['nginx_conf']} /etc/nginx/sites-available/pkica-web.conf")
            print("sudo ln -sf /etc/nginx/sites-available/pkica-web.conf /etc/nginx/sites-enabled/pkica-web.conf")
            print("sudo nginx -t")
            print("sudo systemctl restart nginx")
        else:
            print(f"System nginx: {result['system_nginx']['message']}")
        return 0
    except Exception as exc:
        if str(exc) == "Password was not given but private key is encrypted":
            print("Error: Intermediate CA private key is encrypted.")
            print("Run: pkica web start --intermediate-key-encrypted")
            return 1
        print(f"Error: {exc}")
        return 1


def command_web_stop(args: argparse.Namespace) -> int:
    result = stop_web()
    if result.get("stopped"):
        print(f"pkica web stopped. PID: {result['pid']}")
    else:
        print(result.get("message", "pkica web was not running."))
    return 0


def command_web_status(args: argparse.Namespace) -> int:
    status = web_status()
    print("pkica web status")
    print("-" * 60)
    if status["certificate"]:
        print(f"Web certificate: {status['certificate']['path']}")
        print(f"Valid until:     {status['certificate']['not_valid_after']}")
    else:
        print("Web certificate: not found")
    print(f"FastAPI PID:     {status['pid'] or '-'}")
    print(f"FastAPI status:  {'running' if status['running'] else 'stopped'}")
    print(f"Nginx config:    {status['nginx_conf']}")
    print(f"System nginx:    {'configured by pkica' if status['system_nginx_configured'] else 'not configured by pkica'}")
    return 0

def command_export_trust(args: argparse.Namespace) -> int:
    ensure_ca_directories()

    try:
        root_out = TRUST_EXPORT_DIR / "root.crt.pem"
        intermediate_out = TRUST_EXPORT_DIR / "intermediate.crt.pem"
        chain_out = TRUST_EXPORT_DIR / "ca-chain.pem"

        copy_file(ROOT_CERT_PATH, root_out)
        copy_file(INTERMEDIATE_CERT_PATH, intermediate_out)
        write_chain([INTERMEDIATE_CERT_PATH, ROOT_CERT_PATH], chain_out)

        append_jsonl(
            AUDIT_LOG_PATH,
            {
                "action": "export.trust",
                "output_dir": str(TRUST_EXPORT_DIR),
            },
        )

        print("Trust certificates exported successfully.")
        print(f"Root CA:         {root_out}")
        print(f"Intermediate CA: {intermediate_out}")
        print(f"CA chain:        {chain_out}")
        return 0

    except Exception as exc:
        print(f"Error: {exc}")
        return 1

def command_export_nginx(args: argparse.Namespace) -> int:
    ensure_ca_directories()

    try:
        record = find_issued_record_by_serial(
            db_path=ISSUED_DB_PATH,
            serial_number=args.serial,
        )

        if record.get("status") != "issued":
            print(f"Certificate is not active. Current status: {record.get('status')}")
            return 1

        if record.get("profile") != "server_tls":
            print(f"Certificate profile must be server_tls. Current profile: {record.get('profile')}")
            return 1

        serial = record["serial_number"]
        cert_path = Path(record["cert_path"])
        fullchain_path = Path(record["fullchain_path"])

        export_dir = NGINX_EXPORT_DIR / serial

        cert_out = export_dir / "server.crt.pem"
        fullchain_out = export_dir / "server.fullchain.pem"
        root_out = export_dir / "ca-root.crt.pem"
        intermediate_out = export_dir / "ca-intermediate.crt.pem"
        readme_out = export_dir / "README.txt"

        copy_file(cert_path, cert_out)
        copy_file(fullchain_path, fullchain_out)
        copy_file(ROOT_CERT_PATH, root_out)
        copy_file(INTERMEDIATE_CERT_PATH, intermediate_out)

        readme_out.write_text(
            (
                "Nginx export files\n"
                "==================\n\n"
                "Use these files in a TLS server configuration.\n\n"
                f"Certificate:     {cert_out}\n"
                f"Full chain:      {fullchain_out}\n"
                f"Root CA:         {root_out}\n"
                f"Intermediate CA: {intermediate_out}\n\n"
                "Example Nginx directives:\n\n"
                f"ssl_certificate     {fullchain_out};\n"
                "ssl_certificate_key /path/to/server.key.pem;\n\n"
                "Note: the private key is not exported automatically. "
                "Use the key that was generated for the CSR.\n"
            ),
            encoding="utf-8",
        )

        append_jsonl(
            AUDIT_LOG_PATH,
            {
                "action": "export.nginx",
                "serial_number": serial,
                "output_dir": str(export_dir),
            },
        )

        print("Nginx files exported successfully.")
        print(f"Export dir:   {export_dir}")
        print(f"Certificate:  {cert_out}")
        print(f"Full chain:   {fullchain_out}")
        print(f"Root CA:      {root_out}")
        print(f"README:       {readme_out}")
        print()
        print("Private key is not copied automatically.")
        print("Use the subject key that was used to generate the CSR.")
        return 0

    except Exception as exc:
        print(f"Error: {exc}")
        return 1

# Описание CLI
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pkica")
    subparsers = parser.add_subparsers(dest="command")

    ca_parser = subparsers.add_parser("ca", help="CA management commands")
    ca_subparsers = ca_parser.add_subparsers(dest="ca_command")

    init_root = ca_subparsers.add_parser("init-root", help="Initialize Root CA")
    init_root.add_argument("--algo", choices=["rsa", "ecdsa"], default="rsa")
    init_root.add_argument("--rsa-bits", type=int, default=4096)
    init_root.add_argument("--days", type=int, default=3650)
    init_root.add_argument(
        "--subject",
        required=True,
        help='Example: "C=RU,O=My Org,CN=My Root CA"',
    )
    init_root.add_argument("--encrypt", action="store_true", help="Encrypt private key with password")
    init_root.set_defaults(func=command_init_root)

    init_intermediate = ca_subparsers.add_parser("init-intermediate", help="Initialize Intermediate CA")
    init_intermediate.add_argument("--algo", choices=["rsa", "ecdsa"], default="rsa")
    init_intermediate.add_argument("--rsa-bits", type=int, default=4096)
    init_intermediate.add_argument("--days", type=int, default=1825)
    init_intermediate.add_argument("--pathlen", type=int, default=0)
    init_intermediate.add_argument(
        "--subject",
        required=True,
        help='Example: "C=RU,O=My Org,CN=My Intermediate CA"',
    )
    init_intermediate.add_argument("--encrypt", action="store_true", help="Encrypt private key with password")
    init_intermediate.add_argument(
        "--root-key-encrypted",
        action="store_true",
        help="Use if Root CA private key is encrypted",
    )
    init_intermediate.set_defaults(func=command_init_intermediate)

    key_parser = subparsers.add_parser("key", help="Subject key management commands")
    key_subparsers = key_parser.add_subparsers(dest="key_command")

    key_gen = key_subparsers.add_parser("gen", help="Generate subject private key")
    key_gen.add_argument("--name", required=True, help="Logical name for generated key")
    key_gen.add_argument("--algo", choices=["rsa", "ecdsa"], default="rsa")
    key_gen.add_argument("--rsa-bits", type=int, default=2048)
    key_gen.add_argument("--encrypt", action="store_true", help="Encrypt private key with password")
    key_gen.add_argument("--out", help="Output private key path")
    key_gen.set_defaults(func=command_key_gen)

    csr_parser = subparsers.add_parser("csr", help="CSR management commands")
    csr_subparsers = csr_parser.add_subparsers(dest="csr_command")

    csr_gen = csr_subparsers.add_parser("gen", help="Generate certificate signing request")
    csr_gen.add_argument("--name", required=True, help="Logical name for generated CSR")
    csr_gen.add_argument("--key", required=True, help="Path to subject private key")
    csr_gen.add_argument("--key-encrypted", action="store_true", help="Use if private key is encrypted")
    csr_gen.add_argument("--cn", required=True, help="Common Name")
    csr_gen.add_argument("--org", help="Organization name")
    csr_gen.add_argument("--country", default="RU", help="Country code")
    csr_gen.add_argument("--san-dns", action="append", default=[], help="DNS name for SAN")
    csr_gen.add_argument("--san-ip", action="append", default=[], help="IP address for SAN")
    csr_gen.add_argument("--out", help="Output CSR path")
    csr_gen.set_defaults(func=command_csr_gen)

    cert_parser = subparsers.add_parser("cert", help="Certificate management commands")
    cert_subparsers = cert_parser.add_subparsers(dest="cert_command")

    cert_issue = cert_subparsers.add_parser("issue", help="Issue certificate from CSR")
    cert_issue.add_argument("--csr", help="Path to CSR file")
    cert_issue.add_argument("--req-id", type=int, help="Issue certificate from approved request")
    cert_issue.add_argument(
        "--profile",
        choices=["server_tls", "client_tls"],
        help="Certificate profile",
    )
    cert_issue.add_argument("--days", type=int, default=365)
    cert_issue.add_argument(
        "--intermediate-key-encrypted",
        action="store_true",
        help="Use if Intermediate CA private key is encrypted",
    )
    cert_issue.set_defaults(func=command_cert_issue)

    cert_show = cert_subparsers.add_parser("show", help="Show certificate information")
    cert_show.add_argument("--serial", help="Certificate serial number")
    cert_show.add_argument("--req-id", type=int, help="Request ID")
    cert_show.set_defaults(func=command_cert_show)

    cert_list = cert_subparsers.add_parser("list", help="List issued certificates")
    cert_list.add_argument(
        "--status",
        choices=["issued", "revoked"],
        help="Filter certificates by status",
    )
    cert_list.add_argument(
        "--profile",
        choices=["server_tls", "client_tls"],
        help="Filter certificates by profile",
    )
    cert_list.set_defaults(func=command_cert_list)

    cert_revoke = cert_subparsers.add_parser("revoke", help="Revoke certificate")
    cert_revoke.add_argument("--serial", required=True, help="Certificate serial number")
    cert_revoke.add_argument(
        "--reason",
        choices=list(REASON_MAP.keys()),
        default="unspecified",
        help="Revocation reason",
    )
    cert_revoke.set_defaults(func=command_cert_revoke)

    req_parser = subparsers.add_parser("req", help="Certificate request commands")
    req_subparsers = req_parser.add_subparsers(dest="req_command")

    req_submit = req_subparsers.add_parser("submit", help="Submit CSR as certificate request")
    req_submit.add_argument("--csr", required=True, help="Path to CSR file")
    req_submit.add_argument(
        "--profile",
        choices=["server_tls", "client_tls"],
        required=True,
        help="Requested certificate profile",
    )
    req_submit.set_defaults(func=command_req_submit)

    req_list = req_subparsers.add_parser("list", help="List certificate requests")
    req_list.add_argument(
        "--status",
        choices=["pending", "approved", "issued", "rejected"],
        help="Filter requests by status",
    )
    req_list.set_defaults(func=command_req_list)

    req_approve = req_subparsers.add_parser("approve", help="Approve certificate request")
    req_approve.add_argument("--req-id", type=int, required=True, help="Request ID")
    req_approve.set_defaults(func=command_req_approve)

    req_reject = req_subparsers.add_parser("reject", help="Reject certificate request")
    req_reject.add_argument("--req-id", type=int, required=True, help="Request ID")
    req_reject.add_argument("--reason", required=True, help="Rejection reason")
    req_reject.set_defaults(func=command_req_reject)

    crl_parser = subparsers.add_parser("crl", help="CRL management commands")
    crl_subparsers = crl_parser.add_subparsers(dest="crl_command")

    crl_publish = crl_subparsers.add_parser("publish", help="Publish certificate revocation list")
    crl_publish.add_argument("--days", type=int, default=7, help="CRL validity period in days")
    crl_publish.add_argument(
        "--intermediate-key-encrypted",
        action="store_true",
        help="Use if Intermediate CA private key is encrypted",
    )
    crl_publish.set_defaults(func=command_crl_publish)

    verify_parser = subparsers.add_parser("verify", help="Verify certificate chain and revocation status")
    verify_parser.add_argument("--cert", required=True, help="Certificate path")
    verify_parser.add_argument("--crl", help="CRL path")
    verify_parser.add_argument("--no-crl", action="store_true", help="Do not check certificate revocation")
    verify_parser.set_defaults(func=command_verify)

    reset_parser = subparsers.add_parser("reset", help="Reset all PKI data (DANGEROUS)")
    reset_parser.add_argument(
        "--force",
        action="store_true",
        help="Do not ask for confirmation",
    )
    reset_parser.set_defaults(func=command_reset)

    status_parser = subparsers.add_parser("status", help="Show PKI environment status")
    status_parser.set_defaults(func=command_status)

    export_parser = subparsers.add_parser("export", help="Export certificates for integration")
    export_subparsers = export_parser.add_subparsers(dest="export_command")

    export_trust = export_subparsers.add_parser("trust", help="Export Root and Intermediate CA certificates")
    export_trust.set_defaults(func=command_export_trust)

    export_nginx = export_subparsers.add_parser("nginx", help="Export server certificate files for Nginx")
    export_nginx.add_argument("--serial", required=True, help="Server certificate serial number")
    export_nginx.set_defaults(func=command_export_nginx)

    web_parser = subparsers.add_parser("web", help="Web interface commands")
    web_subparsers = web_parser.add_subparsers(dest="web_command")

    web_start = web_subparsers.add_parser("start", help="Start FastAPI web interface")
    web_start.add_argument("--host", default="pkica.local", help="Public HTTPS host name")
    web_start.add_argument("--port", type=int, default=8000, help="Local FastAPI port")
    web_start.add_argument("--configure-nginx", action="store_true", help="Install generated config into system nginx")
    web_start.add_argument(
        "--intermediate-key-encrypted",
        action="store_true",
        help="Use if Intermediate CA private key is encrypted",
    )
    web_start.set_defaults(func=command_web_start)

    web_stop = web_subparsers.add_parser("stop", help="Stop FastAPI web interface")
    web_stop.set_defaults(func=command_web_stop)

    web_status_parser = web_subparsers.add_parser("status", help="Show web interface status")
    web_status_parser.set_defaults(func=command_web_status)

    return parser

def command_cert_list(args: argparse.Namespace) -> int:
    records = load_issued_records(ISSUED_DB_PATH)

    if args.status:
        records = [
            record for record in records
            if record.get("status") == args.status
        ]

    if args.profile:
        records = [
            record for record in records
            if record.get("profile") == args.profile
        ]

    if not records:
        print("No certificates found.")
        return 0

    print(f"{'SERIAL':<42} {'STATUS':<10} {'PROFILE':<12} {'REQ-ID':<8} {'SUBJECT'}")
    print("-" * 110)

    for record in records:
        serial = record.get("serial_number", "-")
        status = record.get("status", "-")
        profile = record.get("profile", "-")
        request_id = record.get("request_id", "-")
        subject = record.get("subject", "-")

        print(
            f"{serial:<42} "
            f"{status:<10} "
            f"{profile:<12} "
            f"{str(request_id):<8} "
            f"{subject}"
        )

    return 0

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not hasattr(args, "func"):
        parser.print_help()
        return 1

    try:
        return args.func(args)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
