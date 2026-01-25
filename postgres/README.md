# Postgres Provisioning System

Standalone database provisioning system with Postgres, Go API, and Nginx reverse proxy.

## Quick Start

```bash
cd postgres/
docker-compose up -d
```

This starts three services:
- **Postgres** — PostgreSQL 15 (internal only, 1GB RAM optimized)
- **Golang** — DB provisioning API (port 8080 internally)
- **Nginx** — HTTP gateway (port 80)

## Architecture

```
[ External Network ]
        |
        | HTTP
        v
[ Nginx :80 ]
        |
        | (internal docker network)
        |
        +---> /provision     → Golang API
        +---> /health        → Golang health
                 |
                 → Postgres (superadmin only)
```

**Security Model:**
- Postgres superuser (`postgres:superadmin`) — internal only, never shared
- Apps created via API get isolated users with LIMITED privileges
- Each app user:
  - Can only access their own database
  - Cannot create databases or roles
  - Cannot see other apps' data

## API

### POST /provision

Provision a new database and user.

**Request:**
```bash
curl -X POST http://localhost/provision \
  -H "Content-Type: application/json" \
  -d '{
    "app_name": "myapp",
    "admin_key": "sk_..."
  }'
```

**Required:**
- `app_name`: 3-32 chars, lowercase alphanumeric + underscore
- `admin_key`: Logged on startup (check `docker-compose logs`)

**Response (201):**
```json
{
  "connection_string": "postgres://app_myapp_user:password@postgres:5432/app_myapp?sslmode=disable"
}
```

Use this connection string directly in your app.

**Errors:**
- `400`: Invalid app_name or missing field
- `401`: Invalid admin_key
- `409`: App already exists
- `500`: Database error

### GET /health

Check provisioner status.

```bash
curl http://localhost/health
```

Response:
```json
{
  "status": "ok"
}
```

## Admin Key

The admin key is **randomly generated on every startup** and logged:

```bash
docker-compose logs golang | grep "ADMIN KEY"
```

Output:
```
golang     | 🔑 ADMIN KEY: sk_xxxxxxxxx
```

**Important:** Keep this key secret. It's required for all provisioning requests.

## File Structure

```
postgres/
├── docker-compose.yml      # Orchestration (postgres, golang, nginx)
├── nginx.conf              # Nginx config (routes /provision to golang)
├── .env                    # Empty (hardcoded superadmin creds)
├── .gitignore
├── postgres.conf           # Tuned for 1GB RAM
├── pg_hba.conf             # Auth rules (internal docker network only)
├── init/                   # Init SQL (runs once on first start)
│   ├── 01-create-users.sql
│   ├── 02-create-databases.sql
│   └── 03-grants.sql
├── golang/                 # Go provisioning service (ONLY provisioner)
│   ├── main.go             # API + admin key generation
│   ├── go.mod
│   ├── go.sum
│   └── Dockerfile
├── backups/                # Backup directory (manually managed)
└── README.md               # This file
```

**Note:** The `golang/` folder is the only provisioning service used. It:
- Generates a random admin key on startup
- Connects to Postgres as superadmin
- Creates isolated databases and users for apps
- Returns connection strings only

## Logs

Watch all services:

```bash
docker-compose logs -f
```

Or specific service:

```bash
docker-compose logs -f golang
docker-compose logs -f postgres
docker-compose logs -f nginx
```

## Examples

### Provision app

```bash
ADMIN_KEY=$(docker-compose logs golang | grep "ADMIN KEY" | grep -oP 'sk_\w+' | head -1)

curl -X POST http://localhost/provision \
  -H "Content-Type: application/json" \
  -d "{
    \"app_name\": \"api\",
    \"admin_key\": \"$ADMIN_KEY\"
  }"
```

### Connect with psql

```bash
# Extract connection string from provision response
psql "postgres://app_api_user:password@localhost:5432/app_api"
```

### Use in Node.js

```javascript
const { Client } = require('pg');

const client = new Client({
  connectionString: 'postgres://app_api_user:...@localhost:5432/app_api'
});

await client.connect();
```

### Use in Python

```python
import psycopg2

conn = psycopg2.connect(
    "dbname=app_api user=app_api_user password=... host=localhost"
)
```

## Management

### Check status

```bash
docker-compose ps
```

### Connect to Postgres (superadmin)

```bash
docker-compose exec postgres psql -U postgres
```

Inside psql:
```sql
-- List all databases
\l

-- List all users
\du

-- List tables in a database
\c app_myapp
\dt
```

### Backup

```bash
docker-compose exec postgres pg_dumpall -U postgres > backups/backup-$(date +%F).sql
```

### Restart services

```bash
docker-compose restart golang
```

### Stop all

```bash
docker-compose down
```

Data persists in Docker volume `postgres_data`.

## Configuration

### Postgres Tuning

Edit `postgres.conf` for memory/connection limits (currently tuned for 1GB RAM):

```conf
shared_buffers = 256MB
work_mem = 4MB
max_connections = 50
```

Then restart: `docker-compose restart postgres`

### Nginx Routes

Edit `nginx.conf` to add more routes. Current routes:

- `POST /provision` → Golang provisioner
- `GET /health` → Golang health check
- `GET /` → Nginx health check

## Security Checklist

- ✅ Postgres superuser never exposed to apps
- ✅ Apps get isolated databases
- ✅ Apps get restricted users (no superuser, no create DB/role)
- ✅ Admin key changes on every restart
- ✅ Postgres only listens on internal Docker network
- ✅ Public network only touches Nginx
- ✅ Nginx proxies to isolated internal network

## Scaling

**Hit limits?**

1. **More RAM** → increase `shared_buffers`, `work_mem`, `effective_cache_size` in `postgres.conf`
2. **More apps** → just call `/provision` with new app names
3. **More connections** → increase `max_connections` in `postgres.conf`
4. **Connection pooling** → add PgBouncer between Nginx and Postgres
5. **High availability** → switch to managed Postgres (Supabase, RDS, Neon)

## Troubleshooting

### "admin_key" not working

Admin key changes on restart. Check logs:

```bash
docker-compose logs golang | grep "ADMIN KEY"
```

### Postgres won't start

Check logs:

```bash
docker-compose logs postgres
```

Common issues:
- Port 5432 already in use: change `ports` in docker-compose.yml
- Data corruption: remove `postgres_data` volume (⚠️ deletes everything)

### Can't provision database

1. Verify nginx is running: `curl http://localhost/health`
2. Check admin key: `docker-compose logs golang | grep "ADMIN KEY"`
3. Check provisioner logs: `docker-compose logs golang`

## License

MIT
