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

### Backup

```bash
docker-compose exec postgres pg_dumpall -U postgres > backups/backup-$(date +%F).sql
```

