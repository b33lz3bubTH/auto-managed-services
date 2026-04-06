# n8n Docker Setup
### Single Instance | PostgreSQL | Auto-Backups

Lightweight setup for **4 GB RAM** servers or local devices. No domain required.

---

## Architecture

```
http://<your-ip>:5678 → n8n Main (UI + Webhooks + Scheduler + Execution)
                              ↓ reads/writes
                         PostgreSQL 16
                              ↓ daily backups
                          ./backups/
```

### Resource allocation (~4 GB total)

| Service       | RAM   |
|---------------|-------|
| PostgreSQL    | 1 GB  |
| n8n Main      | 2 GB  |
| pgbackup      | ~128M |
| **Total**     | **~3.1 GB** |

---

## Quick Start

### 1. Prerequisites

```bash
# Docker 24+ and Docker Compose v2
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER && newgrp docker
```

### 2. Clone / copy files

```bash
mkdir ~/n8n && cd ~/n8n
# Place docker-compose.yml, .env, init-db.sh, update.sh here
chmod +x update.sh init-db.sh
mkdir -p backups
```

### 3. Configure .env

```bash
nano .env
```

Required variables:

```bash
POSTGRES_DB=n8n
POSTGRES_USER=n8n_user
POSTGRES_PASSWORD=<CHANGE_ME>     # openssl rand -hex 32
N8N_ENCRYPTION_KEY=<CHANGE_ME>    # openssl rand -hex 32
N8N_JWT_SECRET=<CHANGE_ME>        # openssl rand -hex 32
TIMEZONE=UTC

# For remote server access (replace with your server IP):
WEBHOOK_URL=http://YOUR_SERVER_IP:5678/
N8N_EDITOR_BASE_URL=http://YOUR_SERVER_IP:5678/

# For local use, leave defaults (http://localhost:5678/)
```
### 3.5 Generate the ssl

`./generate-ssl.sh`

### 4. Start the stack

```bash
docker compose up -d
```

Check everything is healthy:

```bash
docker compose ps
docker compose logs -f n8n
```

### 5. Access n8n

- **Local device:** `http://localhost:5678`
- **Remote server:** `http://<your-server-ip>:5678`

On first visit you'll be prompted to create an owner account.

---

## Updating n8n

```bash
./update.sh
```

> Tip: Pin a specific version in `docker-compose.yml` for stability:
> `image: docker.n8n.io/n8nio/n8n:1.68.0`

---

## Backups

PostgreSQL is backed up automatically via `pgbackup`:
- Daily backups kept for **7 days**
- Weekly backups kept for **4 weeks**
- Monthly backups kept for **6 months**

Backups are stored in `./backups/`.

### Restore from backup

```bash
docker compose stop n8n
gunzip -c ./backups/last/n8n_20240101.sql.gz | \
  docker compose exec -T postgres psql -U n8n_user -d n8n
docker compose start n8n
```

---

## Useful Commands

```bash
docker compose ps                  # Service status
docker compose logs -f n8n         # Live logs
docker stats                       # Resource usage
docker compose restart n8n         # Restart n8n

# PostgreSQL shell
docker compose exec postgres psql -U n8n_user -d n8n
```

---

## Security Notes

- No SSL in this setup (HTTP only). If you need HTTPS, put a reverse proxy with a self-signed cert in front, or use a VPN/SSH tunnel.
- For remote servers, consider restricting port 5678 access via firewall to known IPs.
- Back up your `N8N_ENCRYPTION_KEY` — losing it means losing all stored credentials.
- Set `.env` permissions: `chmod 600 .env`

```bash
# Firewall: only allow your IP to access n8n
sudo ufw allow 22/tcp
sudo ufw allow from YOUR_IP to any port 5678
sudo ufw enable
```
