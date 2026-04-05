#!/bin/bash
# n8n SSL Certificate Generator
# Generates self-signed certificates for local testing or provides Let's Encrypt integration

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSL_DIR="$SCRIPT_DIR/ssl"
DOMAIN="${1:-localhost}"

mkdir -p "$SSL_DIR"

echo "🔐 Generating SSL certificates for domain: $DOMAIN"

# Generate private key and certificate
openssl req -x509 -newkey rsa:2048 -keyout "$SSL_DIR/key.pem" -out "$SSL_DIR/cert.pem" \
  -days 365 -nodes \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=$DOMAIN"

chmod 644 "$SSL_DIR/cert.pem"
chmod 600 "$SSL_DIR/key.pem"

echo "✅ SSL certificates generated successfully!"
echo "📁 Location: $SSL_DIR/"
echo "🔒 Cert: $SSL_DIR/cert.pem"
echo "🔑 Key: $SSL_DIR/key.pem"
echo ""
echo "📝 NOTE: These are self-signed certificates for testing."
echo "⚠️  For production, use Let's Encrypt or proper CA-signed certificates."
echo ""
echo "🚀 Ready to start: docker compose up"
