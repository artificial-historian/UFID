from __future__ import annotations

from pathlib import Path
from contextlib import closing, redirect_stdout
from io import BytesIO, StringIO
import gzip
import sys
import unittest
import uuid
import zipfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".vendor"))
sys.path.insert(0, str(ROOT / "src"))

from ufid.add import MAX_NESTED_ARCHIVE_DEPTH, main as add_main
from ufid.archives import (
    ARCHIVE_SUFFIXES,
    _parse_7z_list_output,
    iter_archive_entries,
    iter_archive_payload_entries,
    looks_like_archive_path,
)
from ufid.database import connect, list_files
from ufid.paths import default_user_data_dir

SCRATCH = default_user_data_dir() / "test-runs"


def metadata_values(record: dict, name: str) -> list[str]:
    return [item["value"] for item in record["metadata"] if item["name"] == name]


def encrypted_zip_payload() -> bytes:
    payload = BytesIO()
    with zipfile.ZipFile(payload, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("secret.txt", "classified")

    data = bytearray(payload.getvalue())
    for signature, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        index = data.find(signature)
        while index != -1:
            flags = int.from_bytes(data[index + flag_offset : index + flag_offset + 2], "little")
            data[index + flag_offset : index + flag_offset + 2] = (flags | 0x1).to_bytes(
                2,
                "little",
            )
            index = data.find(signature, index + 4)
    return bytes(data)


class ArchiveTests(unittest.TestCase):
    def test_default_nested_archive_depth_is_128(self) -> None:
        self.assertEqual(MAX_NESTED_ARCHIVE_DEPTH, 128)

    def test_archive_suffixes_include_external_and_cd_image_formats(self) -> None:
        for suffix in (".7z", ".rar", ".cab", ".arj", ".lzh", ".iso", ".dmg", ".nrg", ".chd"):
            self.assertIn(suffix, ARCHIVE_SUFFIXES)
        self.assertTrue(looks_like_archive_path("game.iso"))
        self.assertTrue(looks_like_archive_path("software.7z"))
        self.assertTrue(looks_like_archive_path("disk.nrg"))

    def test_single_file_gzip_is_treated_as_archive_member(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        gz_path = SCRATCH / f"single-{uuid.uuid4().hex}.txt.gz"
        gz_path.write_bytes(gzip.compress(b"hello gzip"))

        entries = iter_archive_entries(gz_path)

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].archive_path, gz_path.name.removesuffix(".gz"))
        self.assertEqual(entries[0].payload, b"hello gzip")

    def test_nested_gzip_payload_uses_archive_path_hint(self) -> None:
        entries = iter_archive_payload_entries(
            gzip.compress(b"nested gzip"),
            name_hint="folder/payload.bin.gz",
        )

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].archive_path, "payload.bin")
        self.assertEqual(entries[0].payload, b"nested gzip")

    def test_7z_technical_listing_parser_handles_files_dirs_and_encryption(self) -> None:
        listing = """
Path = sample.iso
Type = Iso
Physical Size = 1234

----------
Path = empty
Folder = +
Size = 0

Path = docs/readme.txt
Folder = -
Size = 5
Encrypted = -

Path = secret.bin
Folder = -
Size = 8
Encrypted = +
"""

        members = _parse_7z_list_output(listing)

        self.assertEqual([member.path for member in members], ["empty", "docs/readme.txt", "secret.bin"])
        self.assertTrue(members[0].is_directory)
        self.assertEqual(members[1].size, 5)
        self.assertTrue(members[2].encrypted)

    def test_add_zip_records_file_members_and_empty_directories(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        archive_path = SCRATCH / f"archive-{uuid.uuid4().hex}.zip"
        db_path = SCRATCH / f"archive-{uuid.uuid4().hex}.sqlite"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("docs/readme.txt", "hello from archive")
            archive.writestr("empty-folder/", "")

        with redirect_stdout(StringIO()):
            exit_code = add_main(
                [
                    "--db",
                    str(db_path),
                    str(archive_path),
                    "--description",
                    "Archive smoke",
                ]
            )

        with closing(connect(db_path)) as connection:
            files = list_files(connection)
            parent = next(item for item in files if item["description"] == "Archive smoke")
            members = parent["archive_members"]
            file_member = next(
                item for item in members if item["archive_path"] == "docs/readme.txt"
            )
            empty_dir = next(
                item for item in members if item["archive_path"] == "empty-folder"
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(len(members), 2)
        self.assertIsNotNone(file_member["child_file_id"])
        self.assertIsNone(empty_dir["child_file_id"])

    def test_add_zip_recurses_into_nested_archives(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        archive_path = SCRATCH / f"outer-{uuid.uuid4().hex}.zip"
        db_path = SCRATCH / f"nested-archive-{uuid.uuid4().hex}.sqlite"

        inner_payload = BytesIO()
        with zipfile.ZipFile(inner_payload, "w") as inner:
            inner.writestr("nested/file.txt", "nested payload")
            inner.writestr("inner-empty/", "")

        with zipfile.ZipFile(archive_path, "w") as outer:
            outer.writestr("archives/inner.zip", inner_payload.getvalue())

        with redirect_stdout(StringIO()):
            exit_code = add_main(
                [
                    "--db",
                    str(db_path),
                    str(archive_path),
                    "--description",
                    "Nested archive smoke",
                ]
            )

        with closing(connect(db_path)) as connection:
            files = list_files(connection)
            outer_record = next(
                item for item in files if item["description"] == "Nested archive smoke"
            )
            inner_member = next(
                item
                for item in outer_record["archive_members"]
                if item["archive_path"] == "archives/inner.zip"
            )
            inner_record = next(
                item for item in files if item["id"] == inner_member["child_file_id"]
            )
            nested_file = next(
                item
                for item in inner_record["archive_members"]
                if item["archive_path"] == "nested/file.txt"
            )
            nested_empty = next(
                item
                for item in inner_record["archive_members"]
                if item["archive_path"] == "inner-empty"
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(len(outer_record["archive_members"]), 1)
        self.assertEqual(len(inner_record["archive_members"]), 2)
        self.assertIsNotNone(nested_file["child_file_id"])
        self.assertIsNone(nested_empty["child_file_id"])

    def test_corrupt_zip_is_recorded_as_archive_error_metadata(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        archive_path = SCRATCH / f"corrupt-{uuid.uuid4().hex}.zip"
        db_path = SCRATCH / f"corrupt-archive-{uuid.uuid4().hex}.sqlite"
        archive_path.write_bytes(b"PK\x03\x04not enough zip data")

        with redirect_stdout(StringIO()):
            exit_code = add_main(
                [
                    "--db",
                    str(db_path),
                    str(archive_path),
                    "--description",
                    "Corrupt archive smoke",
                ]
            )

        with closing(connect(db_path)) as connection:
            files = list_files(connection)
            parent = next(item for item in files if item["description"] == "Corrupt archive smoke")

        errors = metadata_values(parent, "archive_error")
        self.assertEqual(exit_code, 0)
        self.assertFalse(parent["archive_members"])
        self.assertTrue(errors)
        self.assertIn("corrupt", errors[0].lower())

    def test_encrypted_zip_member_is_recorded_as_archive_error_metadata(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        archive_path = SCRATCH / f"encrypted-{uuid.uuid4().hex}.zip"
        db_path = SCRATCH / f"encrypted-archive-{uuid.uuid4().hex}.sqlite"
        archive_path.write_bytes(encrypted_zip_payload())

        with redirect_stdout(StringIO()):
            exit_code = add_main(
                [
                    "--db",
                    str(db_path),
                    str(archive_path),
                    "--description",
                    "Encrypted archive smoke",
                ]
            )

        with closing(connect(db_path)) as connection:
            files = list_files(connection)
            parent = next(
                item for item in files if item["description"] == "Encrypted archive smoke"
            )

        errors = metadata_values(parent, "archive_error")
        self.assertEqual(exit_code, 0)
        self.assertFalse(parent["archive_members"])
        self.assertTrue(errors)
        self.assertIn("secret.txt", errors[0])
        self.assertIn("encrypted", errors[0].lower())


if __name__ == "__main__":
    unittest.main()
