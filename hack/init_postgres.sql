CREATE USER travel2x_admin LOGIN CREATEROLE CREATEDB REPLICATION BYPASSRLS;

-- Travel2X super admin
CREATE USER travel2x_auth_admin NOINHERIT CREATEROLE LOGIN NOREPLICATION PASSWORD 'root';
CREATE SCHEMA IF NOT EXISTS auth AUTHORIZATION travel2x_auth_admin;
GRANT CREATE ON DATABASE postgres TO travel2x_auth_admin;
ALTER USER travel2x_auth_admin SET search_path = 'auth';
