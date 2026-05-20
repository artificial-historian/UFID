\set ON_ERROR_STOP on

\echo 'Loading UFID PostgreSQL schema from docs/database.postgres.sql'
\i docs/database.postgres.sql

\echo 'Running UFID PostgreSQL schema smoke check'
\i deploy/postgres/check_database.sql
