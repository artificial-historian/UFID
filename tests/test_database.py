from __future__ import annotations

from contextlib import closing
from pathlib import Path
import sqlite3
import sys
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".vendor"))
sys.path.insert(0, str(ROOT / "src"))

from ufid.database import (
    IdentityConflict,
    SQLITE_BUSY_TIMEOUT_MS,
    authenticate_user,
    add_archive_member,
    add_file_metadata,
    approve_user_removal_request,
    block_user_removal_request,
    change_user_password,
    clear_goldrush_alerts,
    complete_registration,
    connect,
    count_goldrush_alerts,
    count_goldrush_matches,
    create_goldrush_alert,
    create_invited_user,
    create_session,
    create_user,
    find_file_by_hash,
    get_authenticated_user,
    get_registration_token,
    get_user_by_id,
    import_dat_file_identities,
    list_user_removal_requests,
    list_files,
    list_goldrush_matches,
    list_goldrush_ufid_sources,
    register_user,
    request_user_removal,
    revoke_session,
    scan_goldrush_matches,
    set_user_activation,
    update_user_roles,
    upsert_file_identity,
)
from ufid.auth import verify_password
from ufid.goldrush import parse_logiqx_dat
from ufid.paths import default_user_data_dir

SCRATCH = default_user_data_dir() / "test-runs"


def metadata_value(record: dict, name: str) -> str | None:
    for item in record["metadata"]:
        if item["name"] == name:
            return item["value"]
    return None


class DatabaseTests(unittest.TestCase):
    def test_malformed_password_hash_fails_closed(self) -> None:
        self.assertFalse(verify_password("correct horse battery staple", "bad$hash"))
        self.assertFalse(
            verify_password(
                "correct horse battery staple",
                "pbkdf2_sha256$600000$not-base64!$also-bad!",
            )
        )

    def test_schema_uses_flat_file_hash_columns(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"database-schema-{uuid.uuid4().hex}.sqlite"
        with closing(connect(db_path)) as connection:
            file_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(ufid_file)")
            }
            meta_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(ufid_file_meta)")
            }
            archive_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(ufid_archive_member)")
            }
            session_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(ufid_session)")
            }
            meta_indexes = {
                row["name"]
                for row in connection.execute("PRAGMA index_list(ufid_file_meta)")
            }
            archive_indexes = {
                row["name"]
                for row in connection.execute("PRAGMA index_list(ufid_archive_member)")
            }
            conflict_indexes = {
                row["name"]
                for row in connection.execute("PRAGMA index_list(ufid_identity_conflict)")
            }
            tables = {
                row["name"]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }

        self.assertTrue(
            {"id", "size_bytes", "crc32", "md5", "sha1", "sha256", "blake3"}
            .issubset(file_columns)
        )
        self.assertTrue(
            {"id", "file_id", "metadata_type", "name", "value", "notes", "added_at"}
            .issubset(meta_columns)
        )
        self.assertTrue(
            {"id", "parent_file_id", "child_file_id", "archive_path"}
            .issubset(archive_columns)
        )
        self.assertTrue({"id", "user_id", "token_hash", "expires_at"}.issubset(session_columns))
        self.assertIn("idx_ufid_file_meta_unique", meta_indexes)
        self.assertIn("idx_ufid_archive_member_unique", archive_indexes)
        self.assertIn("idx_ufid_identity_conflict_unique", conflict_indexes)
        self.assertIn("ufid_source", tables)
        self.assertIn("ufid_file_source", tables)
        self.assertIn("ufid_goldrush_user_alert", tables)
        self.assertIn("ufid_goldrush_user_match", tables)
        self.assertNotIn("ufid_hash_algorithm", tables)
        self.assertNotIn("ufid_file_hash", tables)

    def test_sqlite_connections_use_wal_and_busy_timeout(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"database-pragmas-{uuid.uuid4().hex}.sqlite"
        with closing(connect(db_path)) as connection:
            journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
            busy_timeout = connection.execute("PRAGMA busy_timeout").fetchone()[0]
            synchronous = connection.execute("PRAGMA synchronous").fetchone()[0]

        self.assertEqual(str(journal_mode).lower(), "wal")
        self.assertGreaterEqual(int(busy_timeout), SQLITE_BUSY_TIMEOUT_MS)
        self.assertEqual(int(synchronous), 1)

    def test_user_passwords_and_sessions_are_server_side(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"database-auth-{uuid.uuid4().hex}.sqlite"
        with closing(connect(db_path)) as connection:
            created = create_user(
                connection,
                username="alice",
                password="correct horse battery staple",
                roles=["reader", "contributor"],
            )
            self.assertNotIn("password_hash", created)
            self.assertIsNone(
                authenticate_user(
                    connection,
                    username="alice",
                    password="wrong password",
                )
            )
            user = authenticate_user(
                connection,
                username="alice",
                password="correct horse battery staple",
            )
            assert user is not None
            token, session_user = create_session(connection, user_id=int(user["id"]))
            authenticated = get_authenticated_user(connection, token)
            revoked = revoke_session(connection, token)
            after_revoke = get_authenticated_user(connection, token)

        self.assertEqual(created["roles"], ["contributor", "reader"])
        self.assertEqual(session_user.username, "alice")
        self.assertIsNotNone(authenticated)
        assert authenticated is not None
        self.assertIn("contributor", authenticated.roles)
        self.assertTrue(revoked)
        self.assertIsNone(after_revoke)

    def test_usernames_are_canonical_lowercase(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"database-username-{uuid.uuid4().hex}.sqlite"
        with closing(connect(db_path)) as connection:
            created = create_user(
                connection,
                username="Alice",
                password="correct horse battery staple",
                roles=["reader"],
            )
            with self.assertRaises(sqlite3.IntegrityError):
                create_user(
                    connection,
                    username="ALICE",
                    password="correct horse battery staple",
                    roles=["reader"],
                )

        self.assertEqual(created["username"], "alice")

    def test_registration_activation_invites_and_password_changes(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"database-user-lifecycle-{uuid.uuid4().hex}.sqlite"
        with closing(connect(db_path)) as connection:
            registered = register_user(
                connection,
                username="Bob",
                password="correct horse battery staple",
                display_name="Bob",
            )
            self.assertEqual(registered["username"], "bob")
            self.assertEqual(registered["status"], "pending_activation")
            self.assertIsNone(
                authenticate_user(
                    connection,
                    username="bob",
                    password="correct horse battery staple",
                )
            )

            activated = set_user_activation(
                connection,
                user_id=int(registered["id"]),
                active=True,
            )
            assert activated is not None
            authenticated = authenticate_user(
                connection,
                username="bob",
                password="correct horse battery staple",
            )
            assert authenticated is not None
            first_token, _ = create_session(connection, user_id=int(authenticated["id"]))
            second_token, _ = create_session(connection, user_id=int(authenticated["id"]))
            self.assertFalse(
                change_user_password(
                    connection,
                    user_id=int(authenticated["id"]),
                    current_password="wrong password",
                    new_password="new correct horse password",
                    keep_token=first_token,
                )
            )
            self.assertTrue(
                change_user_password(
                    connection,
                    user_id=int(authenticated["id"]),
                    current_password="correct horse battery staple",
                    new_password="new correct horse password",
                    keep_token=first_token,
                )
            )
            self.assertIsNotNone(get_authenticated_user(connection, first_token))
            self.assertIsNone(get_authenticated_user(connection, second_token))
            self.assertIsNone(
                authenticate_user(
                    connection,
                    username="bob",
                    password="correct horse battery staple",
                )
            )
            self.assertIsNotNone(
                authenticate_user(
                    connection,
                    username="bob",
                    password="new correct horse password",
                )
            )

            invited, registration_token, registration = create_invited_user(
                connection,
                username="carol",
                display_name="Carol",
                roles=["reader", "contributor"],
                created_by_user_id=int(registered["id"]),
            )
            self.assertEqual(invited["status"], "invited")
            self.assertEqual(registration["user_id"], invited["id"])
            self.assertIsNotNone(get_registration_token(connection, registration_token))
            completed = complete_registration(
                connection,
                token=registration_token,
                password="carol correct horse password",
            )
            assert completed is not None
            self.assertEqual(completed["status"], "active")
            self.assertIsNone(get_registration_token(connection, registration_token))
            self.assertIsNotNone(
                authenticate_user(
                    connection,
                    username="carol",
                    password="carol correct horse password",
                )
            )
            rerolled = update_user_roles(
                connection,
                user_id=int(completed["id"]),
                roles=["curator", "reader"],
            )
            assert rerolled is not None
            self.assertEqual(rerolled["roles"], ["curator", "reader"])
            with self.assertRaises(ValueError):
                update_user_roles(
                    connection,
                    user_id=int(completed["id"]),
                    roles=[],
                )

    def test_user_removal_requests_can_be_blocked_or_approved(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"database-user-removal-{uuid.uuid4().hex}.sqlite"
        with closing(connect(db_path)) as connection:
            admin = create_user(
                connection,
                username="admin",
                password="correct horse battery staple",
                roles=["admin"],
            )
            user = create_user(
                connection,
                username="delete-me",
                password="correct horse battery staple",
                roles=["reader"],
            )
            request = request_user_removal(connection, user_id=int(user["id"]))
            duplicate = request_user_removal(connection, user_id=int(user["id"]))
            pending = list_user_removal_requests(connection, status="pending")
            blocked = block_user_removal_request(
                connection,
                request_id=int(request["id"]),
                decided_by_user_id=int(admin["id"]),
                notes="Keep audit account",
            )
            second_request = request_user_removal(connection, user_id=int(user["id"]))
            approved = approve_user_removal_request(
                connection,
                request_id=int(second_request["id"]),
                decided_by_user_id=int(admin["id"]),
            )

        self.assertEqual(request["id"], duplicate["id"])
        self.assertEqual(len(pending), 1)
        assert blocked is not None
        self.assertEqual(blocked["status"], "blocked")
        assert approved is not None
        self.assertEqual(approved["status"], "approved")
        self.assertEqual(approved["deleted_user_id"], user["id"])
        with closing(connect(db_path)) as connection:
            self.assertIsNone(get_user_by_id(connection, int(user["id"])))

    def test_upsert_creates_then_enriches_existing_identity(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"database-test-{uuid.uuid4().hex}.sqlite"
        with closing(connect(db_path)) as connection:
            first = upsert_file_identity(
                connection,
                display_name="sample.bin",
                size_bytes=12,
                description=None,
                content_type=None,
                hashes={
                    "crc32": "12345678",
                    "md5": "a" * 32,
                    "sha1": "b" * 40,
                    "sha256": None,
                    "blake3": None,
                },
                metadata={},
            )
            second = upsert_file_identity(
                connection,
                display_name="sample.bin",
                size_bytes=12,
                description="Sample payload",
                content_type="application/octet-stream",
                hashes={
                    "crc32": "12345678",
                    "md5": "a" * 32,
                    "sha1": "b" * 40,
                    "sha256": "c" * 64,
                    "blake3": None,
                },
                metadata={"source": "unit-test"},
            )
            found = find_file_by_hash(connection, "sha1", "b" * 40)

        self.assertTrue(first.created)
        self.assertFalse(first.enriched)
        self.assertEqual(first.file_id, second.file_id)
        self.assertFalse(second.created)
        self.assertTrue(second.enriched)
        self.assertIsNotNone(found)
        assert found is not None
        self.assertEqual(found["description"], "Sample payload")
        self.assertEqual(metadata_value(found, "source"), "unit-test")
        self.assertEqual(found["hashes"]["sha256"], "c" * 64)
        self.assertIsNone(found["hashes"]["blake3"])

    def test_optional_hash_conflict_is_logged_and_rejected(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"database-conflict-{uuid.uuid4().hex}.sqlite"
        with closing(connect(db_path)) as connection:
            created = upsert_file_identity(
                connection,
                display_name="sample.bin",
                size_bytes=12,
                hashes={
                    "crc32": "12345678",
                    "md5": "a" * 32,
                    "sha1": "b" * 40,
                    "sha256": "c" * 64,
                },
            )

            with self.assertRaises(IdentityConflict) as raised:
                upsert_file_identity(
                    connection,
                    display_name="sample.bin",
                    size_bytes=12,
                    hashes={
                        "crc32": "12345678",
                        "md5": "a" * 32,
                        "sha1": "b" * 40,
                        "sha256": "d" * 64,
                    },
                )

            records = list_files(connection, query="sample")

        self.assertTrue(created.created)
        self.assertEqual(len(records), 1)
        self.assertEqual(raised.exception.file_id, created.file_id)
        self.assertEqual(raised.exception.conflict_type, "optional_hash_mismatch")
        self.assertEqual(len(records[0]["identity_conflicts"]), 1)
        self.assertEqual(
            records[0]["identity_conflicts"][0]["conflict_type"],
            "optional_hash_mismatch",
        )

    def test_required_hash_overlap_is_logged_but_kept_as_distinct_identity(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"database-required-overlap-{uuid.uuid4().hex}.sqlite"
        with closing(connect(db_path)) as connection:
            first = upsert_file_identity(
                connection,
                display_name="sample-a.bin",
                size_bytes=12,
                hashes={"crc32": "12345678", "md5": "a" * 32, "sha1": "b" * 40},
            )
            second = upsert_file_identity(
                connection,
                display_name="sample-b.bin",
                size_bytes=12,
                hashes={"crc32": "12345678", "md5": "a" * 32, "sha1": "c" * 40},
            )
            records = list_files(connection, query="sample")

        self.assertTrue(first.created)
        self.assertTrue(second.created)
        self.assertEqual(len(records), 2)
        for record in records:
            self.assertEqual(len(record["identity_conflicts"]), 2)
            self.assertEqual(
                {
                    conflict["conflict_type"]
                    for conflict in record["identity_conflicts"]
                },
                {"required_hash_overlap"},
            )

    def test_upsert_requires_exact_size_and_rejects_size_mismatch(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"database-size-{uuid.uuid4().hex}.sqlite"
        with closing(connect(db_path)) as connection:
            upsert_file_identity(
                connection,
                display_name="sample.bin",
                size_bytes=12,
                hashes={"crc32": "12345678", "md5": "a" * 32, "sha1": "b" * 40},
            )

            with self.assertRaises(ValueError):
                upsert_file_identity(
                    connection,
                    display_name="missing-size.bin",
                    size_bytes=None,
                    hashes={"crc32": "87654321", "md5": "c" * 32, "sha1": "d" * 40},
                )

            second = upsert_file_identity(
                connection,
                display_name="same-hash-different-size.bin",
                size_bytes=13,
                hashes={"crc32": "12345678", "md5": "a" * 32, "sha1": "b" * 40},
            )
            found_at_12 = find_file_by_hash(
                connection,
                "sha1",
                "b" * 40,
                size_bytes=12,
            )
            found_at_13 = find_file_by_hash(
                connection,
                "sha1",
                "b" * 40,
                size_bytes=13,
            )

        self.assertTrue(second.created)
        self.assertIsNotNone(found_at_12)
        self.assertIsNotNone(found_at_13)
        assert found_at_12 is not None
        assert found_at_13 is not None
        self.assertEqual(found_at_12["size_bytes"], 12)
        self.assertEqual(found_at_13["size_bytes"], 13)

    def test_upsert_requires_crc32_md5_and_sha1(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"database-required-{uuid.uuid4().hex}.sqlite"
        with closing(connect(db_path)) as connection:
            with self.assertRaises(ValueError):
                upsert_file_identity(
                    connection,
                    display_name="missing-required.bin",
                    size_bytes=12,
                    hashes={"crc32": "12345678", "md5": "a" * 32},
                )

    def test_import_dat_file_identities_creates_ufid_records(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"database-dat-import-{uuid.uuid4().hex}.sqlite"
        summary = parse_logiqx_dat(
            f"""<?xml version="1.0"?>
<datafile>
  <header>
    <name>UFID DAT</name>
  </header>
  <game name="Complete Set">
    <rom name="complete.bin" size="5" crc="11111111" md5="{'a' * 32}" sha1="{'b' * 40}" sha256="{'c' * 64}" />
    <rom name="partial.bin" size="7" crc="22222222" />
  </game>
</datafile>
"""
        )
        with closing(connect(db_path)) as connection:
            user = create_user(
                connection,
                username="dat-import-user",
                password="correct horse battery staple",
                roles=["reader"],
            )
            result = import_dat_file_identities(
                connection,
                records=summary.alerts,
                dat_filename="ufid.dat",
            )
            duplicate = import_dat_file_identities(
                connection,
                records=summary.alerts,
                dat_filename="ufid.dat",
            )
            files = list_files(connection, query="complete.bin")
            ufid_sources = list_goldrush_ufid_sources(
                connection,
                user_id=int(user["id"]),
            )
            source_links = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT s.name, s.description, fs.external_reference
                    FROM ufid_file_source fs
                    JOIN ufid_source s ON s.id = fs.source_id
                    JOIN ufid_file f ON f.id = fs.file_id
                    WHERE f.sha1 = ?
                    ORDER BY s.name, fs.external_reference
                    """,
                    ("b" * 40,),
                ).fetchall()
            ]

        self.assertEqual(result["received"], 2)
        self.assertEqual(result["valid"], 1)
        self.assertEqual(result["created"], 1)
        self.assertEqual(result["skipped"], 1)
        self.assertIn("Required hashes are missing: md5, sha1", result["errors"][0]["error"])
        self.assertEqual(duplicate["created"], 0)
        self.assertEqual(duplicate["unchanged"], 1)
        self.assertEqual(len(files), 1)
        imported = files[0]
        self.assertEqual(imported["display_name"], "complete.bin")
        self.assertEqual(imported["description"], "Complete Set")
        self.assertEqual(imported["hashes"]["sha256"], "c" * 64)
        self.assertEqual(metadata_value(imported, "source"), "logiqx_dat")
        self.assertEqual(metadata_value(imported, "dat_source_name"), "UFID DAT")
        self.assertEqual(metadata_value(imported, "dat_filename"), "ufid.dat")
        self.assertEqual(
            ufid_sources,
            [
                {
                    "source_value": "logiqx_dat",
                    "label": "Logiqx DAT",
                    "hit_count": 0,
                }
            ],
        )
        self.assertEqual(
            source_links,
            [
                {
                    "name": "logiqx_dat",
                    "description": "Logiqx DAT",
                    "external_reference": "ufid.dat",
                }
            ],
        )

    def test_upsert_rejects_malformed_hash_values(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"database-malformed-hash-{uuid.uuid4().hex}.sqlite"
        with closing(connect(db_path)) as connection:
            with self.assertRaises(ValueError):
                upsert_file_identity(
                    connection,
                    display_name="bad.bin",
                    size_bytes=12,
                    hashes={"crc32": "not-hex!", "md5": "a" * 32, "sha1": "b" * 40},
                )

    def test_structured_metadata_rows_are_appendable(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"database-meta-{uuid.uuid4().hex}.sqlite"
        with closing(connect(db_path)) as connection:
            created = upsert_file_identity(
                connection,
                display_name=None,
                size_bytes=12,
                hashes={"crc32": "12345678", "md5": "a" * 32, "sha1": "b" * 40},
                metadata=[
                    {
                        "metadata_type": "url",
                        "name": "vendor_page",
                        "value": "https://example.test/file",
                        "notes": "Reference URL",
                    },
                    {
                        "metadata_type": "text",
                        "name": "filename",
                        "value": "sample.bin",
                    },
                ],
            )
            found = find_file_by_hash(connection, "md5", "a" * 32, size_bytes=12)

        self.assertTrue(created.created)
        self.assertIsNotNone(found)
        assert found is not None
        self.assertEqual(found["display_name"], "sample.bin")
        self.assertEqual(metadata_value(found, "vendor_page"), "https://example.test/file")

    def test_metadata_can_be_added_without_hash_reupsert(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"database-meta-add-{uuid.uuid4().hex}.sqlite"
        with closing(connect(db_path)) as connection:
            created = upsert_file_identity(
                connection,
                display_name="sample.bin",
                size_bytes=12,
                hashes={"crc32": "12345678", "md5": "a" * 32, "sha1": "b" * 40},
            )
            enriched = add_file_metadata(
                connection,
                file_id=created.file_id,
                metadata=[
                    {
                        "metadata_type": "text",
                        "name": "archive_error",
                        "value": "secret.zip: encrypted member",
                    }
                ],
            )
            duplicate = add_file_metadata(
                connection,
                file_id=created.file_id,
                metadata=[
                    {
                        "metadata_type": "text",
                        "name": "archive_error",
                        "value": "secret.zip: encrypted member",
                    }
                ],
            )
            found = find_file_by_hash(connection, "sha1", "b" * 40, size_bytes=12)

        self.assertTrue(enriched)
        self.assertFalse(duplicate)
        self.assertIsNotNone(found)
        assert found is not None
        self.assertEqual(metadata_value(found, "archive_error"), "secret.zip: encrypted member")

    def test_archive_members_allow_empty_directory_rows(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"database-archive-member-{uuid.uuid4().hex}.sqlite"
        with closing(connect(db_path)) as connection:
            parent = upsert_file_identity(
                connection,
                display_name="archive.zip",
                size_bytes=12,
                hashes={"crc32": "12345678", "md5": "a" * 32, "sha1": "b" * 40},
            )
            child = upsert_file_identity(
                connection,
                display_name="child.txt",
                size_bytes=5,
                hashes={"crc32": "87654321", "md5": "c" * 32, "sha1": "d" * 40},
            )
            file_row_created = add_archive_member(
                connection,
                parent_file_id=parent.file_id,
                child_file_id=child.file_id,
                archive_path="folder/child.txt",
            )
            empty_row_created = add_archive_member(
                connection,
                parent_file_id=parent.file_id,
                child_file_id=None,
                archive_path="empty-folder",
            )
            parent_record = list_files(connection, query="archive.zip")[0]

        self.assertTrue(file_row_created)
        self.assertTrue(empty_row_created)
        self.assertEqual(len(parent_record["archive_members"]), 2)

    def test_goldrush_matches_include_topmost_internet_archive_parent(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"database-goldrush-ia-parent-{uuid.uuid4().hex}.sqlite"
        with closing(connect(db_path)) as connection:
            user = create_user(
                connection,
                username="goldrush-user",
                password="correct horse battery staple",
                roles=["reader", "contributor"],
            )
            other_user = create_user(
                connection,
                username="goldrush-other",
                password="correct horse battery staple",
                roles=["reader", "contributor"],
            )
            parent = upsert_file_identity(
                connection,
                display_name="ia-archive.zip",
                size_bytes=100,
                hashes={"crc32": "11111111", "md5": "a" * 32, "sha1": "b" * 40},
                metadata=[
                    {
                        "metadata_type": "text",
                        "name": "source",
                        "value": "internet_archive",
                    },
                    {
                        "metadata_type": "text",
                        "name": "ia_identifier",
                        "value": "ia-top-item",
                    },
                    {
                        "metadata_type": "url",
                        "name": "ia_item_url",
                        "value": "https://archive.org/details/ia-top-item",
                    },
                    {
                        "metadata_type": "url",
                        "name": "ia_file_url",
                        "value": "https://archive.org/download/ia-top-item/ia-archive.zip",
                    },
                    {
                        "metadata_type": "text",
                        "name": "ia_file_name",
                        "value": "ia-archive.zip",
                    },
                    {
                        "metadata_type": "text",
                        "name": "ia_file_format",
                        "value": "ZIP",
                    },
                ],
            )
            child = upsert_file_identity(
                connection,
                display_name="inside.bin",
                size_bytes=7,
                hashes={"crc32": "22222222", "md5": "c" * 32, "sha1": "d" * 40},
            )
            add_archive_member(
                connection,
                parent_file_id=parent.file_id,
                child_file_id=child.file_id,
                archive_path="inside.bin",
            )
            create_goldrush_alert(
                connection,
                user_id=int(user["id"]),
                name="Watched child",
                description="Should resolve IA parent",
                hashes={"sha1": "d" * 40},
            )

            before_scan_matches = list_goldrush_matches(
                connection,
                user_id=int(user["id"]),
            )
            scan_result = scan_goldrush_matches(connection, user_id=int(user["id"]))
            duplicate_scan_result = scan_goldrush_matches(
                connection,
                user_id=int(user["id"]),
            )
            matches = list_goldrush_matches(connection, user_id=int(user["id"]))
            ia_source_matches = list_goldrush_matches(
                connection,
                user_id=int(user["id"]),
                ufid_sources=["internet_archive"],
            )
            other_source_matches = list_goldrush_matches(
                connection,
                user_id=int(user["id"]),
                ufid_sources=["manual_upload"],
            )
            ia_source_count = count_goldrush_matches(
                connection,
                user_id=int(user["id"]),
                ufid_sources=["internet_archive"],
            )
            ufid_sources = list_goldrush_ufid_sources(
                connection,
                user_id=int(user["id"]),
            )
            other_matches = list_goldrush_matches(
                connection,
                user_id=int(other_user["id"]),
            )

        self.assertEqual(before_scan_matches, [])
        self.assertEqual(scan_result, {"matched": 1, "created": 1})
        self.assertEqual(duplicate_scan_result, {"matched": 1, "created": 0})
        self.assertEqual(len(matches), 1)
        self.assertEqual(ia_source_matches, matches)
        self.assertEqual(other_source_matches, [])
        self.assertEqual(ia_source_count, 1)
        self.assertEqual(
            ufid_sources,
            [
                {
                    "source_value": "internet_archive",
                    "label": "Internet Archive",
                    "hit_count": 1,
                }
            ],
        )
        self.assertEqual(other_matches, [])
        self.assertEqual(
            matches[0]["file"]["source"],
            {
                "source_file_id": parent.file_id,
                "source_value": "internet_archive",
                "label": "Internet Archive",
                "description": "Internet Archive",
                "external_reference": "https://archive.org/download/ia-top-item/ia-archive.zip",
            },
        )
        internet_archive = matches[0]["file"]["internet_archive"]
        self.assertIsNotNone(internet_archive)
        assert internet_archive is not None
        self.assertEqual(internet_archive["source_file_id"], parent.file_id)
        self.assertEqual(internet_archive["identifier"], "ia-top-item")
        self.assertEqual(
            internet_archive["item_url"],
            "https://archive.org/details/ia-top-item",
        )
        self.assertEqual(internet_archive["file_name"], "ia-archive.zip")
        self.assertEqual(internet_archive["file_format"], "ZIP")

    def test_clear_goldrush_alerts_only_removes_current_user_rows(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"database-goldrush-clear-{uuid.uuid4().hex}.sqlite"
        with closing(connect(db_path)) as connection:
            user = create_user(
                connection,
                username="clear-user",
                password="correct horse battery staple",
                roles=["reader", "contributor"],
            )
            other_user = create_user(
                connection,
                username="clear-other",
                password="correct horse battery staple",
                roles=["reader", "contributor"],
            )
            upsert_file_identity(
                connection,
                display_name="watched.bin",
                size_bytes=5,
                hashes={"crc32": "11111111", "md5": "a" * 32, "sha1": "b" * 40},
            )
            create_goldrush_alert(
                connection,
                user_id=int(user["id"]),
                name="Watched one",
                description="First clear target",
                hashes={"md5": "a" * 32},
            )
            create_goldrush_alert(
                connection,
                user_id=int(user["id"]),
                name="Watched two",
                description="Second clear target",
                hashes={"sha1": "b" * 40},
            )
            other_alert = create_goldrush_alert(
                connection,
                user_id=int(other_user["id"]),
                name="Watched one",
                description="First clear target",
                hashes={"md5": "a" * 32},
            )
            duplicate_other_alert = create_goldrush_alert(
                connection,
                user_id=int(other_user["id"]),
                name="Watched one",
                description="First clear target",
                hashes={"md5": "a" * 32},
            )
            before_count = count_goldrush_alerts(connection, user_id=int(user["id"]))
            other_before_count = count_goldrush_alerts(
                connection,
                user_id=int(other_user["id"]),
            )
            scan_goldrush_matches(connection, user_id=int(user["id"]))
            scan_goldrush_matches(connection, user_id=int(other_user["id"]))
            before_match_count = len(
                list_goldrush_matches(connection, user_id=int(user["id"]))
            )
            other_before_match_count = len(
                list_goldrush_matches(connection, user_id=int(other_user["id"]))
            )
            deleted = clear_goldrush_alerts(connection, user_id=int(user["id"]))
            after_count = count_goldrush_alerts(connection, user_id=int(user["id"]))
            other_after_count = count_goldrush_alerts(
                connection,
                user_id=int(other_user["id"]),
            )
            after_match_count = len(
                list_goldrush_matches(connection, user_id=int(user["id"]))
            )
            other_after_match_count = len(
                list_goldrush_matches(connection, user_id=int(other_user["id"]))
            )
            deleted_again = clear_goldrush_alerts(connection, user_id=int(user["id"]))

        self.assertEqual(before_count, 2)
        self.assertTrue(other_alert["created"])
        self.assertFalse(duplicate_other_alert["created"])
        self.assertEqual(other_before_count, 1)
        self.assertEqual(before_match_count, 2)
        self.assertEqual(other_before_match_count, 1)
        self.assertEqual(deleted, 2)
        self.assertEqual(after_count, 0)
        self.assertEqual(other_after_count, 1)
        self.assertEqual(after_match_count, 0)
        self.assertEqual(other_after_match_count, 1)
        self.assertEqual(deleted_again, 0)



if __name__ == "__main__":
    unittest.main()
