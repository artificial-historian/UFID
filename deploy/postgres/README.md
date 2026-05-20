# UFID PostgreSQL Backend Setup

Run these commands from the repository root unless noted otherwise.

## 1. Create Database And API Role

Edit the placeholder password first:

```bash
nano deploy/postgres/create_database_and_role.sql
```

Then run the bootstrap script as a PostgreSQL superuser:

```bash
sudo -u postgres psql -f deploy/postgres/create_database_and_role.sql
```

The script is intentionally small and explicit. For an existing database, change
the role password with `ALTER ROLE ufid_api PASSWORD '...'` instead of re-running
the create statements.

## 2. Load Schema

Load the canonical UFID schema and immediately run the smoke check:

```bash
psql "postgresql://ufid_api:CHANGE_ME_STRONG_PASSWORD@127.0.0.1:5432/ufid" \
  -f deploy/postgres/install_schema.sql
```

`deploy/postgres/install_schema.sql` is a `psql` script. It includes:

- `docs/database.postgres.sql`
- `deploy/postgres/check_database.sql`

If you use a GUI SQL client, run `docs/database.postgres.sql` first and then
`deploy/postgres/check_database.sql`.

## 3. Create First Admin

Install UFID with PostgreSQL support, then create the first administrator
directly through the database connection:

```bash
python -m pip install -e ".[postgres]"
ufid-auth create-user \
  --database-url "postgresql://ufid_api:CHANGE_ME_STRONG_PASSWORD@127.0.0.1:5432/ufid" \
  --username admin \
  --role reader \
  --role contributor \
  --role curator \
  --role admin
```

The command prompts for a password and stores only a PBKDF2 password hash.

## 4. Run API Behind nginx

Use these deployment templates:

- `deploy/env/ufid-api.env.example`
- `deploy/systemd/ufid-api.service`
- `deploy/nginx/ufid.conf`

The intended production path is:

```text
clients -> HTTPS nginx -> 127.0.0.1:8765 ufid-pg-server -> local PostgreSQL
```

PostgreSQL does not need to be exposed outside the server.
