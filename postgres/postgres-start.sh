#!/bin/sh
set -e

CERT_SRC="/var/lib/postgresql/certs"
CERT_DST="/var/lib/postgresql/data/certs"

if [ -f "${CERT_SRC}/server.key" ] && [ -f "${CERT_SRC}/server.crt" ]; then
  mkdir -p "${CERT_DST}"
  cp -f "${CERT_SRC}/server.key" "${CERT_DST}/server.key"
  cp -f "${CERT_SRC}/server.crt" "${CERT_DST}/server.crt"
  if [ -f "${CERT_SRC}/ca.crt" ]; then
    cp -f "${CERT_SRC}/ca.crt" "${CERT_DST}/ca.crt"
  fi
  chown -R postgres:postgres "${CERT_DST}"
  chmod 600 "${CERT_DST}/server.key"
  chmod 644 "${CERT_DST}/server.crt"
  if [ -f "${CERT_DST}/ca.crt" ]; then
    chmod 644 "${CERT_DST}/ca.crt"
  fi
fi

exec docker-entrypoint.sh "$@"
