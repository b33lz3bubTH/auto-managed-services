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
curl -X POST http://localhost:8010/provision \
  -H "Content-Type: application/json" \
  -d '{
    "app_name": "ritu_martan_dhamdhere",
    "admin_key": "sk_5vzDv-uoSxIewf4Vj3s3C1WTED6Di2CS"
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


### Backup

```bash
docker-compose exec postgres pg_dumpall -U postgres > backups/backup-$(date +%F).sql
```