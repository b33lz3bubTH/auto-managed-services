-- Create PgBouncer auth lookup user
CREATE ROLE pgbouncer_auth WITH LOGIN PASSWORD '${PGBOUNCER_AUTH_PASSWORD:-pgbouncer_auth_pass}';

-- Grant necessary permissions for auth_query
GRANT pg_read_all_settings TO pgbouncer_auth;
GRANT pg_read_all_stats TO pgbouncer_auth;

-- Grant access to pg_shadow for password hash lookup
GRANT SELECT ON pg_shadow TO pgbouncer_auth;
