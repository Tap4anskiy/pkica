#!/usr/bin/env bash
set -euo pipefail

echo "=== PKICA full flow test ==="

ROOT_PASS="rootpass"
INTER_PASS="interpass"
SERVER1_PASS="server1pass"
SERVER2_PASS="server2pass"
CLIENT_PASS="clientpass"

echo
echo "[1/23] Check pkica command"
pkica --help > /dev/null

echo
echo "[2/23] Init Root CA"
pkica ca init-root \
  --algo rsa \
  --rsa-bits 4096 \
  --days 3650 \
  --subject "C=RU,O=Rudnev CA,CN=Rudnev Root CA" \
  --encrypt <<EOF
$ROOT_PASS
$ROOT_PASS
EOF

echo
echo "[3/23] Init Intermediate CA"
pkica ca init-intermediate \
  --algo rsa \
  --rsa-bits 4096 \
  --days 1825 \
  --pathlen 0 \
  --subject "C=RU,O=Rudnev CA,CN=Rudnev Intermediate CA" \
  --encrypt \
  --root-key-encrypted <<EOF
$ROOT_PASS
$INTER_PASS
$INTER_PASS
EOF

echo
echo "[4/23] Generate server-01 key"
pkica key gen \
  --name web-01 \
  --algo rsa \
  --rsa-bits 2048 \
  --encrypt <<EOF
$SERVER1_PASS
$SERVER1_PASS
EOF

echo
echo "[5/23] Generate server-01 CSR"
pkica csr gen \
  --name web-01 \
  --key data/subjects/keys/web-01.key.pem \
  --key-encrypted \
  --cn web-01.lab \
  --org "Rudnev CA" \
  --country RU \
  --san-dns web-01.lab \
  --san-ip 192.168.56.10 <<EOF
$SERVER1_PASS
EOF

echo
echo "[6/23] Submit server-01 request"
pkica req submit \
  --csr data/subjects/csrs/web-01.csr.pem \
  --profile server_tls

echo
echo "[7/23] Approve server-01 request"
pkica req approve --req-id 1

echo
echo "[8/23] Issue server-01 certificate"
pkica cert issue \
  --req-id 1 \
  --days 365 \
  --intermediate-key-encrypted <<EOF
$INTER_PASS
EOF

SERVER1_SERIAL=$(python3 - <<'PY'
import json
from pathlib import Path
records = json.loads(Path("data/db/issued.json").read_text())
print(records[-1]["serial_number"])
PY
)

echo "Server-01 serial: $SERVER1_SERIAL"

echo
echo "[9/23] Generate server-02 key"
pkica key gen \
  --name web-02 \
  --algo rsa \
  --rsa-bits 2048 \
  --encrypt <<EOF
$SERVER2_PASS
$SERVER2_PASS
EOF

echo
echo "[10/23] Generate server-02 CSR"
pkica csr gen \
  --name web-02 \
  --key data/subjects/keys/web-02.key.pem \
  --key-encrypted \
  --cn web-02.lab \
  --org "Rudnev CA" \
  --country RU \
  --san-dns web-02.lab \
  --san-dns www.web-02.lab \
  --san-ip 192.168.56.11 <<EOF
$SERVER2_PASS
EOF

echo
echo "[11/23] Submit server-02 request"
pkica req submit \
  --csr data/subjects/csrs/web-02.csr.pem \
  --profile server_tls

echo
echo "[12/23] Approve server-02 request"
pkica req approve --req-id 2

echo
echo "[13/23] Issue server-02 certificate"
pkica cert issue \
  --req-id 2 \
  --days 365 \
  --intermediate-key-encrypted <<EOF
$INTER_PASS
EOF

SERVER2_SERIAL=$(python3 - <<'PY'
import json
from pathlib import Path
records = json.loads(Path("data/db/issued.json").read_text())
print(records[-1]["serial_number"])
PY
)

echo "Server-02 serial: $SERVER2_SERIAL"

echo
echo "[14/23] Generate client-01 key"
pkica key gen \
  --name client-01 \
  --algo rsa \
  --rsa-bits 2048 \
  --encrypt <<EOF
$CLIENT_PASS
$CLIENT_PASS
EOF

echo
echo "[15/23] Generate client-01 CSR"
pkica csr gen \
  --name client-01 \
  --key data/subjects/keys/client-01.key.pem \
  --key-encrypted \
  --cn client-01 \
  --org "Rudnev CA" \
  --country RU <<EOF
$CLIENT_PASS
EOF

echo
echo "[16/23] Submit client-01 request"
pkica req submit \
  --csr data/subjects/csrs/client-01.csr.pem \
  --profile client_tls

echo
echo "[17/23] Approve client-01 request"
pkica req approve --req-id 3

echo
echo "[18/23] Issue client-01 certificate"
pkica cert issue \
  --req-id 3 \
  --days 365 \
  --intermediate-key-encrypted <<EOF
$INTER_PASS
EOF

CLIENT_SERIAL=$(python3 - <<'PY'
import json
from pathlib import Path
records = json.loads(Path("data/db/issued.json").read_text())
print(records[-1]["serial_number"])
PY
)

echo "Client-01 serial: $CLIENT_SERIAL"

echo
echo "[19/23] Show certificates"
pkica cert show --serial "$SERVER1_SERIAL"
pkica cert show --serial "$SERVER2_SERIAL"
pkica cert show --serial "$CLIENT_SERIAL"

echo
echo "[20/23] List certificates"
pkica cert list

echo
echo "[21/23] Verify all certificates before revoke"
pkica verify --cert "data/issued/${SERVER1_SERIAL}.crt.pem"
pkica verify --cert "data/issued/${SERVER2_SERIAL}.crt.pem"
pkica verify --cert "data/issued/${CLIENT_SERIAL}.crt.pem"

echo
echo "[22/23] Export trust and nginx files"
pkica export trust
pkica export nginx --serial "$SERVER1_SERIAL"
pkica export nginx --serial "$SERVER2_SERIAL"

echo
echo "[23/23] Publish CRL, revoke server-01, republish CRL and verify"
pkica crl publish \
  --days 7 \
  --intermediate-key-encrypted <<EOF
$INTER_PASS
EOF

pkica verify \
  --cert "data/issued/${SERVER2_SERIAL}.crt.pem" \
  --crl data/crl/intermediate.crl.pem

pkica cert revoke \
  --serial "$SERVER1_SERIAL" \
  --reason keyCompromise

pkica crl publish \
  --days 7 \
  --intermediate-key-encrypted <<EOF
$INTER_PASS
EOF

if pkica verify \
  --cert "data/issued/${SERVER1_SERIAL}.crt.pem" \
  --crl data/crl/intermediate.crl.pem; then
  echo "ERROR: revoked server-01 certificate passed verification"
  exit 1
else
  echo "OK: revoked server-01 certificate failed verification as expected"
fi

pkica verify \
  --cert "data/issued/${SERVER2_SERIAL}.crt.pem" \
  --crl data/crl/intermediate.crl.pem

pkica verify \
  --cert "data/issued/${CLIENT_SERIAL}.crt.pem" \
  --crl data/crl/intermediate.crl.pem

echo
echo "=== Final status ==="
pkica status

echo
echo "=== Full flow test completed successfully ==="