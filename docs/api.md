# UFID API Contract

The HTTP API is versioned under `/api/v1`.

All `/api/v1` endpoints require authentication except registration, invitation
completion, login, and session inspection. Clients authenticate with either:

- an HttpOnly `ufid_session` cookie issued by `POST /api/v1/auth/login`, used by
  the browser UI;
- an `Authorization: Bearer <token>` header, used by CLI applications.

Read endpoints require `reader`. Write endpoints that create or change
user-managed data require `contributor`; the Goldrush match search endpoint uses
`reader` because it materializes a derived cache for the current user's own
alerts. Managing users and removal requests requires `admin`.

Usernames are stored as canonical lowercase values. Login is therefore
case-insensitive for users created through the UFID tools/API.

## Authentication

```http
POST /api/v1/auth/login
Content-Type: application/json
```

Request:

```json
{
  "username": "alice",
  "password": "correct horse battery staple"
}
```

Response:

```json
{
  "authenticated": true,
  "token": "session-token-for-cli-bearer-auth",
  "token_type": "Bearer",
  "expires_at": "2026-06-17T10:00:00+00:00",
  "user": {
    "id": 1,
    "username": "alice",
    "display_name": "Alice",
    "roles": ["contributor", "reader"],
    "session_id": 1,
    "expires_at": "2026-06-17T10:00:00+00:00"
  }
}
```

The response also sets an HttpOnly `ufid_session` cookie for browser use.

```http
GET /api/v1/auth/session
Authorization: Bearer <token>
```

Returns the current user, or `{ "authenticated": false }`.

```http
POST /api/v1/auth/logout
Authorization: Bearer <token>
```

Revokes the current session and clears the browser cookie.

```http
POST /api/v1/auth/register
Content-Type: application/json
```

Creates a self-registered reader account. The account cannot log in until an
admin activates it:

```json
{
  "username": "bob",
  "password": "correct horse battery staple",
  "display_name": "Bob"
}
```

```http
POST /api/v1/auth/registration/complete
Content-Type: application/json
```

Completes an admin-created registration link, sets the user's password, activates
the account, creates a session, and sets the browser cookie:

```json
{
  "token": "registration-token-from-admin-link",
  "password": "correct horse battery staple",
  "display_name": "Bob"
}
```

```http
GET /api/v1/auth/me
POST /api/v1/auth/me/password
POST /api/v1/auth/me/removal-request
Authorization: Bearer <token>
```

Registered users can load their profile, change their password, and request
account removal. Password changes require the current password and revoke other
active sessions for the account.

```http
POST /api/v1/auth/users
Authorization: Bearer <admin-token>
Content-Type: application/json
```

Creates a user. If `password` is omitted, the server creates an inactive invited
user and returns a one-time registration link:

```json
{
  "username": "bob",
  "display_name": "Bob",
  "roles": ["reader", "contributor"]
}
```

Admin user lifecycle endpoints:

```http
GET /api/v1/auth/users
POST /api/v1/auth/users/{user_id}/activate
POST /api/v1/auth/users/{user_id}/deactivate
POST /api/v1/auth/users/{user_id}/roles
POST /api/v1/auth/users/{user_id}/invite
DELETE /api/v1/auth/users/{user_id}
GET /api/v1/auth/removal-requests?status=pending
POST /api/v1/auth/removal-requests/{request_id}/approve
POST /api/v1/auth/removal-requests/{request_id}/block
Authorization: Bearer <admin-token>
```

`POST /api/v1/auth/users/{user_id}/roles` accepts a JSON body such as
`{"roles": ["reader", "contributor"]}` and replaces the user's assigned roles.
Admins cannot remove their own `admin` role.

Approving a removal request deletes that user account and all dependent sessions,
roles, registration tokens, and pending removal rows through database cascades.

## Search By Hash

```http
GET /api/v1/files/by-hash?algorithm=sha1&value=<hex>&size=<bytes>
Authorization: Bearer <token>
```

The `size` query parameter is optional for manual searches, but local file
lookups should send it. UFID stores exact filesize for every file record.

Returns:

```json
{
  "found": true,
  "count": 1,
  "file": {
    "id": 1,
    "size_bytes": 1234,
    "crc32": "12345678",
    "md5": "0123456789abcdef0123456789abcdef",
    "sha1": "0123456789abcdef0123456789abcdef01234567",
    "sha256": null,
    "blake3": null,
    "display_name": "example.bin",
    "description": "Example file",
    "content_type": "application/octet-stream",
    "hashes": {
      "crc32": "12345678",
      "md5": "0123456789abcdef0123456789abcdef",
      "sha1": "0123456789abcdef0123456789abcdef01234567",
      "sha256": null,
      "blake3": null
    },
    "metadata": [
      {
        "id": 1,
        "file_id": 1,
        "metadata_type": "text",
        "name": "filename",
        "value": "example.bin",
        "notes": null,
        "added_at": "2026-05-18 10:00:00"
      }
    ],
    "archive_members": [
      {
        "id": 1,
        "parent_file_id": 1,
        "child_file_id": 2,
        "archive_path": "docs/readme.txt"
      },
      {
        "id": 2,
        "parent_file_id": 1,
        "child_file_id": null,
        "archive_path": "empty-folder"
      }
    ],
    "identity_conflicts": [
      {
        "id": 1,
        "file_id": 1,
        "related_file_id": null,
        "conflict_type": "optional_hash_mismatch",
        "algorithm": "sha256",
        "existing_value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "incoming_value": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "incoming_size_bytes": 1234,
        "incoming_crc32": "12345678",
        "incoming_md5": "0123456789abcdef0123456789abcdef",
        "incoming_sha1": "0123456789abcdef0123456789abcdef01234567",
        "notes": "Same required identity tuple was observed with a different sha256 value",
        "logged_at": "2026-05-18 10:00:00"
      }
    ]
  },
  "files": []
}
```

When no record exists:

```json
{ "found": false }
```

## Browse File Records

```http
GET /api/v1/files?limit=200&offset=0&sort=id&direction=desc&q=<filter>
Authorization: Bearer <token>
```

`limit` is capped at 200. `sort` can be `id`, `name`, `size`, `crc32`, `md5`,
`sha1`, `sha256`, or `blake3`; `direction` can be `asc` or `desc`.

Returns:

```json
{
  "files": [],
  "limit": 200,
  "offset": 0,
  "count": 0,
  "total_count": 0,
  "sort": "id",
  "direction": "desc",
  "next_offset": null
}
```

## Goldrush Alerts

Goldrush alerts and stored matches are scoped to the authenticated registered
user. Creating, importing, listing, searching, matching, and clearing alerts
only affects that user's alert set.

```http
POST /api/v1/goldrush/alerts
Content-Type: application/json
Authorization: Bearer <token>
```

Creates a monitoring alert. `name`, `description`, and at least one supported
hash are required. `size_bytes` is optional; when present it must match the UFID
file size for a hit to be reported.

```json
{
  "name": "Goldrush Set",
  "description": "Logiqx DAT or manual context",
  "size_bytes": 1234,
  "hashes": {
    "crc32": "12345678",
    "md5": "0123456789abcdef0123456789abcdef",
    "sha1": "0123456789abcdef0123456789abcdef01234567"
  }
}
```

```http
POST /api/v1/goldrush/import-dat
Content-Type: application/json
Authorization: Bearer <token>
```

Imports Logiqx DAT files in XML or classic text syntax. Imported rows use the
set name as the alert name and the DAT header name as the alert description.

```json
{
  "filename": "example.dat",
  "text": "<datafile>...</datafile>"
}
```

```http
POST /api/v1/goldrush/alerts
Content-Type: application/json
Authorization: Bearer <token>
```

With an `action` payload, erases the current user's Goldrush alerts and returns
the number removed:

```json
{
  "action": "clear"
}
```

Response:

```json
{
  "deleted": 2
}
```

`POST /api/v1/goldrush/alerts/clear` is accepted as a compatibility alias.
`DELETE /api/v1/goldrush/alerts` is also accepted by current servers for API
clients that prefer a method matching the operation.

```http
DELETE /api/v1/goldrush/alerts
Authorization: Bearer <token>
```

```http
GET /api/v1/goldrush/alerts?limit=200&offset=0&q=<filter>
GET /api/v1/goldrush/alert-sources
GET /api/v1/goldrush/ufid-sources
GET /api/v1/goldrush/matches?limit=200&offset=0&q=<filter>&source_key=<alert-list>&ufid_source=<ufid-source>
Authorization: Bearer <token>
```

The `alert-sources` endpoint returns alert-list buckets for the current user's
match filtering. Manual alerts use `source_key=manual`; imported alert lists use
a stable source key derived from their import type and source name. The
`ufid-sources` endpoint returns available UFID source table values. The matches
endpoint accepts repeated `source_key` parameters to restrict stored results to
one or more alert lists, and repeated `ufid_source` parameters to restrict
stored results to one or more UFID source values, including sources inherited
through archive parents.

```http
POST /api/v1/goldrush/matches/search
Content-Type: application/json
Authorization: Bearer <token>
```

Searches current UFID records against the current user's alerts, stores newly
found matches, and returns the number found and newly inserted. Re-running the
same search does not create duplicate stored match rows.

```json
{
  "search": {
    "matched": 2,
    "created": 1
  },
  "total_count": 7
}
```

The matches endpoint loads stored results only. A match is stored when an
existing UFID record has a stored hash matching a Goldrush alert. If the alert
has `size_bytes`, the UFID record must match that exact size as well. When UFID
can trace the matched file to Internet Archive metadata, the match file includes
an `internet_archive` object with the IA item URL. For archive members, that
object points to the topmost archive parent that was ingested from IA.

## Add Or Enrich File Identity

```http
POST /api/v1/files
Content-Type: application/json
Authorization: Bearer <token>
```

Request:

```json
{
  "display_name": "example.bin",
  "size_bytes": 1234,
  "description": "Example file",
  "content_type": "application/octet-stream",
  "hashes": {
    "crc32": "12345678",
    "md5": "0123456789abcdef0123456789abcdef",
    "sha1": "0123456789abcdef0123456789abcdef01234567",
    "sha256": null,
    "blake3": null
  },
  "metadata": [
    {
      "metadata_type": "url",
      "name": "vendor_page",
      "value": "https://example.test/file",
      "notes": "Reference URL"
    }
  ]
}
```

The server still accepts a simple metadata object for CLI compatibility:

```json
{
  "metadata": {
    "source": "local import"
  }
}
```

Response:

```json
{
  "id": 1,
  "created": true,
  "enriched": false
}
```

If an incoming record matches an existing required identity
(`size_bytes`, `crc32`, `md5`, `sha1`) but disagrees with an already stored
optional hash (`sha256` or `blake3`), the backend records an
`optional_hash_mismatch` row in `ufid_identity_conflict` and rejects the write:

```json
{
  "error": "Optional hash conflict for UFID 1: sha256",
  "file_id": 1,
  "conflict_type": "optional_hash_mismatch"
}
```

If an incoming record has the same exact size and shares one or more required
hashes with an existing record, but does not match the full required identity
tuple, UFID stores it as a distinct file and logs `required_hash_overlap`
warnings. This captures possible hash-collision evidence without merging files
that have different full identities.

## Import DAT Rows As UFID File Identities

```http
POST /api/v1/files/import-dat
Content-Type: application/json
Authorization: Bearer <token>
```

Imports Logiqx DAT files in XML or classic text syntax into UFID file identity
records. This is separate from Goldrush DAT alert import. Only rows with exact
`size_bytes`, `crc32`, `md5`, and `sha1` can become UFID file records; partial
hash rows are reported in `errors` and remain suitable for Goldrush alerts.

```json
{
  "filename": "example.dat",
  "text": "<datafile>...</datafile>"
}
```

Imported records link the file to the `logiqx_dat` UFID source and store DAT
provenance as file metadata, including `dat_source_name`, `dat_set_name`,
`dat_entry_name`, and `dat_filename` when supplied.

```json
{
  "source_name": "Example DAT",
  "parsed": 2,
  "received": 2,
  "valid": 1,
  "created": 1,
  "enriched": 0,
  "unchanged": 0,
  "skipped": 1,
  "errors": [
    {
      "index": 1,
      "name": "partial.bin",
      "error": "Required hashes are missing: md5, sha1"
    }
  ]
}
```

## Add Archive Membership

```http
POST /api/v1/archive-members
Content-Type: application/json
Authorization: Bearer <token>
```

Request for a file inside an archive:

```json
{
  "parent_file_id": 1,
  "child_file_id": 2,
  "archive_path": "docs/readme.txt"
}
```

Request for an empty directory inside an archive:

```json
{
  "parent_file_id": 1,
  "child_file_id": null,
  "archive_path": "empty-folder"
}
```

`archive_path` is the internal path from the archive root. It may be `null` for
unstructured archive formats, but empty directory rows must provide a path.
Nested archives use the same relationship recursively: the outer archive points
to the inner archive file, and the inner archive points to its own contents.

Response:

```json
{
  "created": true
}
```

## Add Metadata To Existing File

```http
POST /api/v1/files/1/metadata
Content-Type: application/json
Authorization: Bearer <token>
```

Request:

```json
{
  "metadata": [
    {
      "metadata_type": "text",
      "name": "archive_error",
      "value": "secret.zip: Encrypted ZIP member cannot be read without a password",
      "notes": "Archive scanner could not extract this content"
    }
  ]
}
```

Response:

```json
{
  "enriched": true
}
```

The archive scanner uses this endpoint when an archive or archive member cannot
be extracted. Corrupt archives and encrypted ZIP members are kept as metadata
facts named `archive_error`; they are not inserted as child UFID files because
UFID cannot compute the child file's exact size and required hashes.

## Browser Static Assets

The local and PostgreSQL servers serve packaged web assets by default:

```http
GET /
GET /files.html
GET /goldrush.html
GET /account.html
GET /app.js
GET /files.js
GET /goldrush.js
GET /account.js
GET /styles.css
```

Production deployment can serve the web UI separately as long as CORS and API
base URL configuration are handled explicitly.
