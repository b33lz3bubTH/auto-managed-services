#!/bin/bash
# Creates the n8n user with proper privileges on first start
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    -- Enable useful extensions
    CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
    CREATE EXTENSION IF NOT EXISTS "pg_trgm";
    
    -- Grant all privileges to n8n user
    GRANT ALL PRIVILEGES ON DATABASE $POSTGRES_DB TO $POSTGRES_USER;
    
    -- Set timezone
    ALTER DATABASE $POSTGRES_DB SET timezone TO 'UTC';
    
    \echo 'n8n database initialized successfully.'
EOSQL
