#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="${ROOT_DIR}/certs"

rm -rf "${CERT_DIR}"
mkdir -p "${CERT_DIR}"

openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout "${CERT_DIR}/server.key" \
  -out "${CERT_DIR}/server.crt" \
  -days 3650 \
  -subj "/CN=localhost"

cp "${CERT_DIR}/server.crt" "${CERT_DIR}/ca.crt"

chmod_cmd() {
  if command -v sudo >/dev/null 2>&1; then
    sudo chmod "$@"
  else
    chmod "$@"
  fi
}

# Ensure directory is accessible to container user
chmod_cmd 755 "${CERT_DIR}"

# Keep key readable on host so rootless containers can copy it,
# it will be locked down to 600 inside the container.
chmod_cmd 644 "${CERT_DIR}/server.key"
chmod_cmd 644 "${CERT_DIR}/server.crt" "${CERT_DIR}/ca.crt"

echo "Certs generated successfully"
