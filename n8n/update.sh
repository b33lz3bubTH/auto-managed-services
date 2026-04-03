#!/bin/bash
# =============================================================================
#  n8n Update Script — Pulls latest image and restarts
# =============================================================================

set -euo pipefail

echo "Pulling latest n8n image..."
docker compose pull n8n

echo "Restarting n8n..."
docker compose up -d --force-recreate n8n

echo "Update complete! Current status:"
docker compose ps

echo ""
echo "Tailing n8n logs (Ctrl+C to exit):"
docker compose logs -f --tail=50 n8n
