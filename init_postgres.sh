#!/bin/bash
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
	CREATE USER travel2x_admin LOGIN CREATEROLE CREATEDB REPLICATION BYPASSRLS;

    -- travel2x super admin
    CREATE USER travel2x_auth_admin NOINHERIT CREATEROLE LOGIN NOREPLICATION PASSWORD 'root';
    CREATE SCHEMA IF NOT EXISTS $DB_NAMESPACE AUTHORIZATION travel2x_auth_admin;
    GRANT CREATE ON DATABASE postgres TO travel2x_auth_admin;
    ALTER USER travel2x_auth_admin SET search_path = '$DB_NAMESPACE';
EOSQL