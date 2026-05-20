# UFID: Universal File Identification Database

UFID is a file identity system for computing, storing, searching, and enriching
multi-algorithm file hashsets.

This repository currently contains runnable Python local applications that
establish the core behavior and data model. The backend target is PostgreSQL,
with SQLite available for local/offline use.

Current release target: `0.5.0rc1`.

## Components

- `ufid-lookup`: compute hashes for a file or directory and search known UFID
  records.
- `ufid-add`: compute hashes for a file or directory and insert or enrich UFID
  records. Supported archives are inspected and their file/directory contents
  are linked to the archive record, including nested archives.
- `ufid-auth`: create users directly in a UFID database, log in to an API, and
  persist CLI bearer sessions.
- `ufid-ia-ingest`: discover Internet Archive item files, download and hash
  their bytes, add them to UFID, and inspect supported archive contents.
- `ufid-server`: local HTTP API backed by SQLite for prototype use.
- `ufid-pg-server`: HTTP API backed by PostgreSQL for deployment behind nginx.
- `web/`: static browser interface with drag-and-drop client-side hashing.
- `docs/database.postgres.sql`: PostgreSQL schema for the backend target.

## Quick Start

Install the tools into your active Python environment:

```powershell
python -m pip install -e .
ufid lookup .\some-file.bin
ufid add .\some-file.bin --description "Sample file"
ufid server
```

Runtime databases, logs, caches, downloaded extractor tools, and test scratch
data default to the configured data root. This checkout ships
`ufid.config.toml`, which points to `D:\UFID-data`. Override it with
`UFID_DATA_DIR` or `UFID_CONFIG_FILE` when needed.

From a source checkout without installing, use
`python .\scripts\run_ufid.py <command> ...`; it dispatches to the same package
entry points.

Then open:

```text
http://127.0.0.1:8765
```

When using the API backend, create a user and log in first:

```powershell
ufid auth create-user --db D:\UFID-data\ufid.sqlite --username admin --role reader --role contributor --role admin
ufid auth login --backend http://127.0.0.1:8765 --username admin
ufid lookup --backend http://127.0.0.1:8765 .\some-file.bin
```

Usernames are canonicalized to lowercase when users are created.

Internet Archive ingestion is resumable through a local state database. Start
small, then remove the limits once credentials and server capacity are ready:

```powershell
ufid ia-ingest --backend http://127.0.0.1:8765 --collection software --max-items 1
```

For large Internet Archive ingestion, run the IA metadata/API queue and the
download/analyze queue separately:

```powershell
ufid ia-ingest --mode metadata --collection software
ufid ia-ingest --mode download --backend http://127.0.0.1:8765
```

On Windows, for a local SQLite-only discovery run that starts the web/API server
and then runs IA metadata discovery in the foreground:

```powershell
.\scripts\start_windows_local_ia_discovery.ps1 -MaxItems 1000
```

If the default port is already in use, the script probes the next few ports and
prints the actual local URL. Pass `-Port` or `-PortScanCount` to control this.
Installed environments also expose the same workflow as:

```powershell
ufid-local-ia-discovery --max-items 1000
```

See [docs/internet-archive-ingest.md](docs/internet-archive-ingest.md) for
resume, retry, rate-limit, and archive-handling details.

For broad legacy archive and CD/disk-image extraction, install `7z`/`7zz` or
`bsdtar` on `PATH`. See [docs/archive-extractors.md](docs/archive-extractors.md).
You can also run `python .\scripts\setup_archive_tools.py --download` to set up
portable extractor tools where possible and generate a live coverage report.
Installed environments expose this as `ufid-archive-tools --download`.

## Hash Algorithms

By default, the local applications compute the required identity hashset:

- `crc32`
- `md5`
- `sha1`

The system also knows about optional hashes:

- `sha256`
- `blake3`

The required identity hashset is:

- `crc32`
- `md5`
- `sha1`

Optional hashes may be empty/null:

- `sha256`
- `blake3`

UFID rejects and logs optional hash mismatches for the same required identity.
It also logs same-size required-hash overlaps as identity warnings while keeping
the records distinct unless the full required tuple matches.

The Python local apps currently target Python 3.12 through 3.14. BLAKE3 support is
optional and only needed if you ask the CLI to compute `--algorithm blake3`:

```powershell
python -m pip install -e ".[blake3]"
```

## Production Direction

The recommended production shape is:

- Local apps: Python scripts, sharing one hashing/database/API core across
  lookup and add commands.
- Backend: PostgreSQL, with a flat immutable file table plus metadata, source,
  role, and audit tables.
- Web: static or SPA frontend that hashes local files in the browser and calls
  the backend search API.
- Local mode: SQLite snapshot/import support for offline lookups.

See [docs/architecture.md](docs/architecture.md) and
[docs/api.md](docs/api.md) for the first implementation contract. For a
fully local SQLite setup, see [docs/local-sqlite.md](docs/local-sqlite.md). For
a PostgreSQL deployment behind nginx, see
[docs/deploy-nginx-postgres.md](docs/deploy-nginx-postgres.md) and
[deploy/postgres/README.md](deploy/postgres/README.md).
