# UFID Architecture

## Goals

UFID identifies files by a full hashset and stores human- and machine-readable
metadata about those identities.

The system supports four workflows:

1. Lookup a file or directory against the UFID database.
2. Add or enrich file identity records from a file or directory.
3. Serve search/enrichment workloads from PostgreSQL.
4. Let browser users hash local files client-side and search UFID.

## Major Boundaries

### Core Hashing

The hashing core streams file bytes once and updates all selected algorithms in
parallel. This prevents avoidable multi-pass disk reads and gives the CLIs, API
workers, and import jobs identical output.

### Identity Model

A UFID file identity is one immutable physical-file row: exact file size plus
the supported hash columns. The required identity columns are `size_bytes`,
`crc32`, `md5`, and `sha1`. Optional hash columns such as `sha256` and `blake3`
may be `NULL`.

Human-readable names, descriptions, content classifications, URLs, images, and
other annotations live in appendable `ufid_file_meta` rows.

Identity warnings live in `ufid_identity_conflict`. A disagreement in optional
hashes for the same required identity is recorded as `optional_hash_mismatch`
and rejected, because the same bytes should not produce two different optional
hashes. A same-size file that overlaps on one or more required hashes but does
not match the full required tuple is recorded as `required_hash_overlap` and
kept as a distinct file.

Archive containment is represented separately in `ufid_archive_member`. Archive
rows map one parent UFID file to either a child UFID file or an empty directory
entry. `archive_path` stores the internal path from the archive root.

Archive processing is recursive. If a file inside an archive is itself a
supported archive, UFID first records the outer archive containing that inner
archive file, then records the inner archive as the parent of its own members.
The default recursion ceiling is 128 nested archive levels.

Unreadable archive content is recorded as metadata instead of failing the whole
import. Corrupt archive files, corrupt archive members, and encrypted ZIP
members create `ufid_file_meta` rows named `archive_error`. They do not create
`ufid_archive_member` child rows unless the child bytes can be extracted and
hashed.

### Local Store

SQLite local mode is intended for:

- offline lookup snapshots,
- developer testing,
- single-user/private UFID collections,
- later import/export workflows.

SQLite should mirror the PostgreSQL conceptual model closely enough that native
CLIs can switch storage backends without changing output behavior.

### Backend

The PostgreSQL backend owns canonical UFID state. It should expose a versioned
HTTP API and enforce role-based permissions for enrichment and direct database
submission.

Suggested roles:

- `reader`: search and browse public records.
- `contributor`: submit new file observations and metadata.
- `curator`: edit canonical metadata and merge duplicates.
- `admin`: manage users, roles, and system settings.

### Web Interface

The browser UI should never upload file bytes for normal lookup. It should hash
the file locally through drag-and-drop and submit only hash values to the search
API. Optional upload workflows can be added later as explicit, privileged
analysis actions.

## Directory Layout

```text
docs/
  api.md
  database.postgres.sql
src/
  ufid/
    add.py
    api_client.py
    cli.py
    database.py
    hashing.py
    ia_ingest.py
    local_ia_discovery.py
    lookup.py
    paths.py
    server.py
    web/
web/
  app.js
  index.html
  styles.css
tests/
  test_hashing.py
```

## Local Application Plan

The local applications are installable Python console tools. Python keeps the
Windows and Linux workflows simple while the data model and API stabilize.

The local application core should keep:

- one codebase for Windows and Linux,
- streaming hash computation,
- safe file traversal,
- SQLite local/offline support,
- HTTP backend support for PostgreSQL-backed deployments.
