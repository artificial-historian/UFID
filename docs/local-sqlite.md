# UFID Local SQLite Operation

SQLite mode is fully local: the command line tools and local server read and
write a SQLite database file directly. No PostgreSQL server, nginx, or network
API is required.

## Database File

Every local command accepts `--db`. The database is created automatically if it
does not exist. When `--db` is omitted, the default path is
`D:\UFID-data\ufid.sqlite` from the checked-in `ufid.config.toml`.
The data root can be changed with `UFID_DATA_DIR` or `UFID_CONFIG_FILE`.

```powershell
ufid add .\sample.bin
ufid lookup .\sample.bin
```

## Local Web/API Server

For browser use, create a local user and run the SQLite-backed API/web server:

```powershell
ufid auth create-user `
  --db D:\UFID-data\ufid.sqlite `
  --username admin `
  --role reader `
  --role contributor `
  --role admin

ufid server
```

Then open:

```text
http://127.0.0.1:8765
```

Browser and API access still require login. Direct CLI operations using `--db`
do not require an API session because they access the local database file
directly.

The SQLite server uses one database connection per HTTP request. Connections are
configured with WAL journaling and a 30-second busy timeout so reads can
continue while a write is active and short write bursts wait for locks instead
of failing immediately. If the database is still locked after that timeout, the
API returns `503 Service Unavailable` with `Retry-After: 1`.

## Internet Archive Ingest

Internet Archive ingest can also target SQLite directly. The IA state queue is a
separate SQLite database so discovery and download/analyze work can be run
independently:

```powershell
ufid ia-ingest `
  --mode metadata `
  --collection software

ufid ia-ingest `
  --mode download
```

Use `--backend` instead of `--db` when ingesting into a hosted UFID API.

## Windows All-In-One Discovery

For Windows local-only operation, this script starts the SQLite-backed UFID
web/API server and then runs Internet Archive discovery mode in the foreground:

```powershell
.\scripts\start_windows_local_ia_discovery.ps1 -MaxItems 1000
```

After installation, the same workflow is available as a standalone console
script:

```powershell
ufid-local-ia-discovery --max-items 1000
```

Defaults:

- UFID database: `D:\UFID-data\ufid.sqlite`
- IA state database: `D:\UFID-data\ia-ingest.sqlite`
- cache directory: `D:\UFID-data\ia-cache`
- server URL: `http://127.0.0.1:8765`
- IA mode: `metadata`
- IA collection: `software`

The script writes logs under `D:\UFID-data\logs` and stops the local server when
the discovery run ends. Add `-KeepServerRunning` if you want the server job left
running in the current PowerShell session.

If another local program is already answering on `8765`, the script scans the
next ports and prints the actual URL it chose. Use `-Port` and `-PortScanCount`
to control that behavior.

Useful options:

```powershell
.\scripts\start_windows_local_ia_discovery.ps1 -Collection software -MaxItems 1000
.\scripts\start_windows_local_ia_discovery.ps1 -Query "collection:software AND format:ZIP" -MaxItems 500
.\scripts\start_windows_local_ia_discovery.ps1 -UserAgent "UFID-IA-Ingest/0.8 (contact: you@example.com)"
.\scripts\start_windows_local_ia_discovery.ps1 -Port 8876 -PortScanCount 1
.\scripts\start_windows_local_ia_discovery.ps1 -CreateAdmin -AdminUsername admin
.\scripts\start_windows_local_ia_discovery.ps1 -Debug -MaxItems 100
.\scripts\start_windows_local_ia_discovery.ps1 -NoServer -MaxItems 1000
```

## Schema Parity

The SQLite schema mirrors the PostgreSQL model for current local features:

- `ufid_file`
- `ufid_file_meta`
- `ufid_archive_member`
- `ufid_identity_conflict`
- `ufid_source`
- `ufid_file_source`
- `ufid_goldrush_alert`
- `ufid_user_account`
- `ufid_role`
- `ufid_user_role`
- `ufid_session`
- `ufid_registration_token`
- `ufid_user_removal_request`
- `ufid_goldrush_user_alert`
- `ufid_goldrush_user_match`

The PostgreSQL backend additionally includes `ufid_audit_log` for server-side
auditing.
