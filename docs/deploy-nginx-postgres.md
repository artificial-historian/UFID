# UFID PostgreSQL + nginx Deployment

This deployment keeps PostgreSQL private. Clients talk only to nginx over HTTPS;
nginx serves the static web UI and reverse-proxies API requests to a local UFID
API process bound to `127.0.0.1`.

Security model: `ufid-pg-server` implements password login, server-side
sessions, bearer tokens for CLI clients, HttpOnly cookies for the browser, and
role checks. Use HTTPS at nginx. You may still put the API behind VPN, mTLS, or
nginx basic auth for extra defense.

## Files

- `docs/database.postgres.sql`: canonical PostgreSQL schema.
- `docs/openapi.yaml`: API contract for CLI/web/server compatibility.
- `deploy/postgres/create_database_and_role.sql`: optional database and role bootstrap.
- `deploy/postgres/install_schema.sql`: psql schema-load and smoke-check script.
- `deploy/postgres/check_database.sql`: simple schema smoke check.
- `deploy/postgres/README.md`: backend setup script order and operational notes.
- `deploy/env/ufid-api.env.example`: service environment template.
- `deploy/systemd/ufid-api.service`: systemd service template.
- `deploy/nginx/ufid.conf`: nginx reverse-proxy and static-web template.

## Target Shape

```text
CLI apps / browser
        |
        | HTTPS JSON
        v
nginx :443
        |
        | http://127.0.0.1:8765
        v
ufid-pg-server
        |
        | postgresql://ufid_api@127.0.0.1:5432/ufid
        v
PostgreSQL
```

## Database

Edit the bootstrap password first:

```bash
nano deploy/postgres/create_database_and_role.sql
```

Run as a PostgreSQL superuser:

```bash
sudo -u postgres psql -f deploy/postgres/create_database_and_role.sql
```

Load the schema as the API role from the repository root:

```bash
psql "postgresql://ufid_api:CHANGE_ME_STRONG_PASSWORD@127.0.0.1:5432/ufid" \
  -f deploy/postgres/install_schema.sql
```

If you are using a SQL tool that does not understand `psql` include commands,
run `docs/database.postgres.sql` first, then check the database:

```bash
psql "postgresql://ufid_api:CHANGE_ME_STRONG_PASSWORD@127.0.0.1:5432/ufid" \
  -f deploy/postgres/check_database.sql
```

## API Service

Install UFID on the server:

```bash
sudo useradd --system --home /opt/ufid --shell /usr/sbin/nologin ufid
sudo mkdir -p /opt/ufid/app /opt/ufid/web /etc/ufid
sudo chown -R ufid:ufid /opt/ufid
```

Copy the repository contents to `/opt/ufid/app`, then install:

```bash
cd /opt/ufid/app
python3 -m venv /opt/ufid/venv
/opt/ufid/venv/bin/python -m pip install -e ".[postgres]"
```

Copy web assets:

```bash
cp -r /opt/ufid/app/src/ufid/web/* /opt/ufid/web/
```

Create the service environment:

```bash
sudo cp deploy/env/ufid-api.env.example /etc/ufid/ufid-api.env
sudo nano /etc/ufid/ufid-api.env
sudo chmod 600 /etc/ufid/ufid-api.env
```

Install and start the service:

```bash
sudo cp deploy/systemd/ufid-api.service /etc/systemd/system/ufid-api.service
sudo systemctl daemon-reload
sudo systemctl enable --now ufid-api
sudo systemctl status ufid-api
```

Local check from the server:

```bash
curl http://127.0.0.1:8765/health
```

Create the first admin user directly against PostgreSQL:

```bash
/opt/ufid/venv/bin/ufid-auth create-user \
  --database-url "postgresql://ufid_api:CHANGE_ME_STRONG_PASSWORD@127.0.0.1:5432/ufid" \
  --username admin \
  --role reader \
  --role contributor \
  --role curator \
  --role admin
```

The command prompts for the password and stores only a PBKDF2 password hash.

## nginx

Edit `server_name` and certificate paths in `deploy/nginx/ufid.conf`, then:

```bash
sudo cp deploy/nginx/ufid.conf /etc/nginx/sites-available/ufid.conf
sudo ln -s /etc/nginx/sites-available/ufid.conf /etc/nginx/sites-enabled/ufid.conf
sudo nginx -t
sudo systemctl reload nginx
```

External check:

```bash
curl https://ufid.example.com/health
```

## Client Configuration

The CLI apps should point at the public nginx URL:

```bash
ufid-auth login --backend https://ufid.example.com --username admin
ufid-lookup --backend https://ufid.example.com ./sample.bin
ufid-add --backend https://ufid.example.com ./sample.bin --description "Sample file"
```

`ufid-auth login` stores a bearer session token in the user's home directory
under `.ufid/sessions.json`. The lookup and add applications automatically use
the saved token for the matching backend URL. You can also set
`UFID_API_TOKEN` for non-interactive jobs.

The browser UI uses relative `/api/v1/...` URLs. Copying the packaged
`src/ufid/web/` assets into nginx's document root makes it work from the same
hostname without exposing PostgreSQL or configuring CORS. Browser sessions use
a Secure, HttpOnly `ufid_session` cookie.

## API Endpoints

The reverse proxy must expose:

- `GET /health`
- `POST /api/v1/auth/login`
- `GET /api/v1/auth/session`
- `POST /api/v1/auth/logout`
- `POST /api/v1/auth/users`
- `GET /api/v1/files/by-hash`
- `GET /api/v1/files`
- `GET /api/v1/files/{id}`
- `POST /api/v1/files`
- `POST /api/v1/files/{id}/metadata`
- `POST /api/v1/archive-members`

See `docs/openapi.yaml` for the machine-readable contract and `docs/api.md` for
examples.
