-- Edit the password before running this file as a PostgreSQL superuser.
-- Example:
--   sudo -u postgres psql -f deploy/postgres/create_database_and_role.sql
--
-- This script is for a new PostgreSQL instance. If the role or database already
-- exists, change the role password with ALTER ROLE and load the schema with
-- deploy/postgres/install_schema.sql instead of re-running these CREATE
-- statements.

CREATE ROLE ufid_api LOGIN PASSWORD 'CHANGE_ME_STRONG_PASSWORD';
CREATE DATABASE ufid OWNER ufid_api;
