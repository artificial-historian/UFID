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
    authenticate_user,
    add_archive_member,
    add_file_metadata,
    connect,
    create_session,
    create_user,
    find_file_by_hash,
    get_authenticated_user,
    list_files,
    revoke_session,
    upsert_file_identity,
)
from ufid.auth import verify_password
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
        self.assertNotIn("ufid_hash_algorithm", tables)
        self.assertNotIn("ufid_file_hash", tables)

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



if __name__ == "__main__":
    unittest.main()
