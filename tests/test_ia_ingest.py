from __future__ import annotations

from contextlib import closing, redirect_stdout
from email.message import Message
from io import BytesIO, StringIO
import gzip
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
import uuid
import zipfile
import zlib


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".vendor"))
sys.path.insert(0, str(ROOT / "src"))

from ufid.database import connect, list_files
from ufid.ia_client import (
    DownloadResult,
    IAChecksumMismatch,
    IAFile,
    IAHTTPClient,
    file_url,
    is_metadata_file,
    parse_item_metadata,
    safe_download_path,
    verify_declared_fixity,
)
from ufid.ia_ingest import (
    IAIngestRunner,
    IngestOptions,
    build_parser,
    options_from_args,
    parse_size_limit,
)
from ufid.ia_state import IAIngestState
from ufid.paths import default_user_data_dir

SCRATCH = default_user_data_dir() / "test-runs"


class FakeIAClient:
    def __init__(
        self,
        payload: bytes,
        *,
        declared_sha1: str | None = None,
        omit_file_fields: tuple[str, ...] = (),
        file_name: str = "downloads/archive.zip",
        file_format: str = "ZIP",
        extra_file_records: tuple[dict[str, object], ...] = (),
        extra_file_metadata: dict[str, object] | None = None,
        extra_item_metadata: dict[str, object] | None = None,
        extra_top_level_metadata: dict[str, object] | None = None,
        fail_metadata: bool = False,
        fail_scrape: bool = False,
    ) -> None:
        self.payload = payload
        self.declared_sha1 = declared_sha1 or hashlib.sha1(payload).hexdigest()
        self.omit_file_fields = omit_file_fields
        self.file_name = file_name
        self.file_format = file_format
        self.extra_file_records = extra_file_records
        self.extra_file_metadata = extra_file_metadata or {}
        self.extra_item_metadata = extra_item_metadata or {}
        self.extra_top_level_metadata = extra_top_level_metadata or {}
        self.fail_metadata = fail_metadata
        self.fail_scrape = fail_scrape
        self.scrape_calls = 0
        self.metadata_calls = 0
        self.download_calls = 0

    def scrape(self, **kwargs):
        if self.fail_scrape:
            raise AssertionError("scrape should not be called")
        self.scrape_calls += 1
        return {
            "items": [
                {
                    "identifier": "fake-software-item",
                    "title": "Fake Software Item",
                    "mediatype": "software",
                }
            ],
            "count": 1,
            "total": 1,
            "cursor": None,
        }

    def get_metadata(self, identifier: str):
        if self.fail_metadata:
            raise AssertionError("metadata should not be called")
        self.metadata_calls += 1
        file_record = {
            "name": self.file_name,
            "source": "original",
            "format": self.file_format,
            "size": str(len(self.payload)),
            "md5": hashlib.md5(self.payload).hexdigest(),
            "sha1": self.declared_sha1,
            "crc32": f"{zlib.crc32(self.payload) & 0xffffffff:08x}",
        }
        file_record.update(self.extra_file_metadata)
        for field in self.omit_file_fields:
            file_record.pop(field, None)
        item_metadata = {
            "identifier": identifier,
            "title": "Fake Software Item",
            "mediatype": "software",
            "collection": ["software"],
        }
        item_metadata.update(self.extra_item_metadata)
        response = {
            "metadata": {
                **item_metadata,
            },
            "files": [file_record, *self.extra_file_records],
        }
        response.update(self.extra_top_level_metadata)
        return response

    def download_file(
        self,
        *,
        identifier: str,
        ia_file: IAFile,
        destination: Path,
        resume: bool,
        progress_callback=None,
    ):
        self.download_calls += 1
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(self.payload)
        if progress_callback is not None:
            progress_callback(0, len(self.payload))
            progress_callback(len(self.payload), len(self.payload))
        return DownloadResult(
            path=destination,
            url=file_url(identifier, ia_file.name),
            bytes_written=len(self.payload),
            resumed=False,
        )


class CollectionDiscoveryClient:
    def __init__(self) -> None:
        self.payload = b"child collection payload"
        self.scrape_queries: list[str] = []
        self.metadata_identifiers: list[str] = []
        self.download_calls = 0

    def scrape(self, **kwargs):
        query = kwargs["query"]
        self.scrape_queries.append(query)
        if query == "collection:software":
            return {
                "items": [
                    {
                        "identifier": "software-subcollection",
                        "title": "Software Subcollection",
                        "mediatype": "collection",
                    }
                ],
                "count": 1,
                "total": 1,
                "cursor": None,
            }
        if query == "collection:software-subcollection":
            return {
                "items": [
                    {
                        "identifier": "child-software-item",
                        "title": "Child Software Item",
                        "mediatype": "software",
                    }
                ],
                "count": 1,
                "total": 1,
                "cursor": None,
            }
        raise AssertionError(f"unexpected scrape query: {query}")

    def get_metadata(self, identifier: str):
        self.metadata_identifiers.append(identifier)
        if identifier == "software-subcollection":
            return {
                "metadata": {
                    "identifier": identifier,
                    "title": "Software Subcollection",
                    "mediatype": "collection",
                    "collection": ["software"],
                },
                "files": [],
            }
        if identifier == "child-software-item":
            return {
                "metadata": {
                    "identifier": identifier,
                    "title": "Child Software Item",
                    "mediatype": "software",
                    "collection": ["software-subcollection"],
                },
                "files": [
                    {
                        "name": "child.bin",
                        "source": "original",
                        "format": "Binary",
                        "size": str(len(self.payload)),
                        "md5": hashlib.md5(self.payload).hexdigest(),
                        "sha1": hashlib.sha1(self.payload).hexdigest(),
                        "crc32": f"{zlib.crc32(self.payload) & 0xffffffff:08x}",
                    }
                ],
            }
        raise AssertionError(f"unexpected metadata identifier: {identifier}")

    def download_file(self, **kwargs):
        self.download_calls += 1
        raise AssertionError("metadata mode should not download files")


class CollectionNoGrowthClient:
    def __init__(self) -> None:
        self.scrape_queries: list[str] = []
        self.metadata_calls = 0
        self.download_calls = 0

    def scrape(self, **kwargs):
        query = kwargs["query"]
        self.scrape_queries.append(query)
        if query == "collection:software":
            return {
                "items": [
                    {
                        "identifier": "software-subcollection",
                        "title": "Software Subcollection",
                        "mediatype": "collection",
                    }
                ],
                "count": 1,
                "total": 1,
                "cursor": None,
            }
        if query == "collection:software-subcollection":
            return {
                "items": [
                    {
                        "identifier": "child-software-item",
                        "title": "Child Software Item",
                        "mediatype": "software",
                    }
                ],
                "count": 1,
                "total": 1,
                "cursor": None,
            }
        raise AssertionError(f"unexpected scrape query: {query}")

    def get_metadata(self, identifier: str):
        self.metadata_calls += 1
        raise AssertionError("metadata should not be called without collection growth")

    def download_file(self, **kwargs):
        self.download_calls += 1
        raise AssertionError("download should not be called in metadata mode")


class CollectionGrowthClient(CollectionNoGrowthClient):
    def __init__(self) -> None:
        super().__init__()
        self.payload = b"new child collection payload"

    def get_metadata(self, identifier: str):
        self.metadata_calls += 1
        if identifier != "new-child-software-item":
            raise AssertionError(f"unexpected metadata identifier: {identifier}")
        return {
            "metadata": {
                "identifier": identifier,
                "title": "New Child Software Item",
                "mediatype": "software",
                "collection": ["software-subcollection"],
            },
            "files": [
                {
                    "name": "new-child.bin",
                    "source": "original",
                    "format": "Binary",
                    "size": str(len(self.payload)),
                    "md5": hashlib.md5(self.payload).hexdigest(),
                    "sha1": hashlib.sha1(self.payload).hexdigest(),
                    "crc32": f"{zlib.crc32(self.payload) & 0xffffffff:08x}",
                }
            ],
        }

    def scrape(self, **kwargs):
        query = kwargs["query"]
        self.scrape_queries.append(query)
        if query == "collection:software":
            return {
                "items": [
                    {
                        "identifier": "software-subcollection",
                        "title": "Software Subcollection",
                        "mediatype": "collection",
                    }
                ],
                "count": 1,
                "total": 1,
                "cursor": None,
            }
        if query == "collection:software-subcollection":
            return {
                "items": [
                    {
                        "identifier": "child-software-item",
                        "title": "Child Software Item",
                        "mediatype": "software",
                    },
                    {
                        "identifier": "new-child-software-item",
                        "title": "New Child Software Item",
                        "mediatype": "software",
                    },
                ],
                "count": 2,
                "total": 2,
                "cursor": None,
            }
        raise AssertionError(f"unexpected scrape query: {query}")


class FakeResponse:
    def __init__(
        self,
        payload: bytes,
        headers: Message | None = None,
        status: int = 200,
    ) -> None:
        self.payload = payload
        self._stream = BytesIO(payload)
        self.headers = headers or Message()
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self, size: int = -1) -> bytes:
        return self._stream.read(size)

    def getcode(self) -> int:
        return self.status


def zip_payload() -> bytes:
    payload = BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr("inner/readme.txt", "hello from IA")
    return payload.getvalue()


def ia_file_record(
    name: str,
    payload: bytes,
    *,
    source: str = "original",
    file_format: str = "Binary",
) -> dict[str, object]:
    return {
        "name": name,
        "source": source,
        "format": file_format,
        "size": str(len(payload)),
        "md5": hashlib.md5(payload).hexdigest(),
        "sha1": hashlib.sha1(payload).hexdigest(),
        "crc32": f"{zlib.crc32(payload) & 0xffffffff:08x}",
    }


def metadata_values(file_record: dict[str, object], name: str) -> list[str]:
    metadata = file_record.get("metadata") or []
    assert isinstance(metadata, list)
    return [
        str(item["value"])
        for item in metadata
        if isinstance(item, dict) and item.get("name") == name
    ]


def options(db_path: Path, state_path: Path, cache_path: Path) -> IngestOptions:
    return IngestOptions(
        mode="all",
        query="collection:software",
        crawl_key="unit-test",
        backend=None,
        api_token=None,
        db_path=str(db_path),
        state_db=str(state_path),
        cache_dir=cache_path,
        user_agent="UFID-IA-Ingest-Test/0.1.0 (gpt-5; test)",
        algorithms=("crc32", "md5", "sha1"),
        scrape_count=100,
        timeout=5,
        max_retries=1,
        request_delay_seconds=0,
        download_delay_seconds=0,
        max_items=1,
        max_files=None,
        max_file_bytes=None,
        min_size_bytes=None,
        max_size_bytes=None,
        original_only=False,
        skip_metadata_files=False,
        ia_artifacts=False,
        keep_cache=False,
        retry_failed=False,
        dry_run=False,
        no_archive_scan=False,
        deep_discover_archives=False,
        allow_checksum_mismatch=False,
        discover_collections=False,
        max_collection_depth=1,
        max_collections=None,
        jsonl=False,
        quiet=True,
        debug=False,
    )


class InternetArchiveIngestTests(unittest.TestCase):
    def test_parser_defaults_to_vintagesoftware_with_collection_discovery(self) -> None:
        parsed = build_parser().parse_args([])
        parsed_without_discovery = build_parser().parse_args(
            ["--no-discover-collections"]
        )
        parsed_with_limits = build_parser().parse_args(
            [
                "--mode",
                "download",
                "--min-size",
                "10k",
                "--max-size",
                "100k",
                "--deep-discover-archives",
                "--ia-artifacts",
            ]
        )

        defaults = options_from_args(parsed)
        without_discovery = options_from_args(parsed_without_discovery)
        with_limits = options_from_args(parsed_with_limits)

        self.assertEqual(defaults.query, "collection:vintagesoftware")
        self.assertTrue(defaults.discover_collections)
        self.assertEqual(defaults.max_collection_depth, 1)
        self.assertFalse(defaults.deep_discover_archives)
        self.assertFalse(without_discovery.discover_collections)
        self.assertEqual(with_limits.min_size_bytes, 10 * 1024)
        self.assertEqual(with_limits.max_size_bytes, 100 * 1024)
        self.assertTrue(with_limits.deep_discover_archives)
        self.assertFalse(defaults.ia_artifacts)
        self.assertTrue(with_limits.ia_artifacts)

    def test_parser_rejects_inverted_size_window(self) -> None:
        parsed = build_parser().parse_args(
            ["--min-size", "2M", "--max-size", "1M"]
        )
        with self.assertRaisesRegex(ValueError, "min-size"):
            options_from_args(parsed)

    def test_size_limit_parser_accepts_magnitude_suffixes(self) -> None:
        self.assertEqual(parse_size_limit("100k"), 100 * 1024)
        self.assertEqual(parse_size_limit("2M"), 2 * 1024 * 1024)
        self.assertEqual(parse_size_limit("1.5G"), int(1.5 * 1024**3))
        self.assertEqual(parse_size_limit("42"), 42)

    def test_url_and_metadata_helpers_are_current_shape(self) -> None:
        self.assertEqual(
            file_url("abc", "dir/a#b?.zip"),
            "https://archive.org/download/abc/dir/a%23b%3F.zip",
        )
        path = safe_download_path(SCRATCH / "cache", "abc", "../CON/a?.zip")
        self.assertIn("_CON", str(path))
        item = parse_item_metadata(
            "abc",
            {
                "metadata": {"collection": "software", "title": "ABC"},
                "files": [{"name": "a.bin", "size": "3"}],
            },
        )
        self.assertEqual(item.collections, ("software",))
        self.assertEqual(item.files[0].size, 3)
        self.assertTrue(is_metadata_file(IAFile(name="abc_files.xml")))
        self.assertTrue(is_metadata_file(IAFile(name="abc_meta.sqlite")))
        self.assertTrue(is_metadata_file(IAFile(name="abc_meta.xml")))
        self.assertTrue(is_metadata_file(IAFile(name="meta.xml")))
        self.assertTrue(is_metadata_file(IAFile(name="anything.bin", format="Metadata")))
        self.assertFalse(is_metadata_file(IAFile(name="profiles.xml")))

    def test_http_client_retries_429_with_retry_after(self) -> None:
        headers = Message()
        headers["Retry-After"] = "0"
        calls = {"count": 0}

        def fake_urlopen(request, timeout):
            calls["count"] += 1
            if calls["count"] == 1:
                raise HTTPError(
                    request.full_url,
                    429,
                    "Too Many Requests",
                    headers,
                    BytesIO(b'{"error": "slow down"}'),
                )
            return FakeResponse(b'{"ok": true}')

        client = IAHTTPClient(
            user_agent="UFID-IA-Ingest-Test/0.1.0",
            max_retries=1,
            request_delay_seconds=0,
            sleep_func=lambda seconds: None,
        )
        with patch("ufid.ia_client.urlopen", fake_urlopen):
            data = client.get_json("https://archive.org/test")

        self.assertEqual(data, {"ok": True})
        self.assertEqual(calls["count"], 2)

    def test_http_client_reports_download_progress(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        payload = b"a" * (1024 * 1024 + 17)
        destination = SCRATCH / f"progress-{uuid.uuid4().hex}.zip"
        events: list[tuple[int, int | None]] = []

        def fake_urlopen(request, timeout):
            return FakeResponse(payload)

        client = IAHTTPClient(
            user_agent="UFID-IA-Ingest-Test/0.1.0",
            max_retries=0,
            download_delay_seconds=0,
            sleep_func=lambda seconds: None,
        )
        with patch("ufid.ia_client.urlopen", fake_urlopen):
            result = client.download_file(
                identifier="fake-software-item",
                ia_file=IAFile(name="downloads/archive.zip", size=len(payload)),
                destination=destination,
                progress_callback=lambda written, total: events.append((written, total)),
            )

        self.assertEqual(result.bytes_written, len(payload))
        self.assertEqual(destination.read_bytes(), payload)
        self.assertEqual(events[0], (0, len(payload)))
        self.assertEqual(events[-1], (len(payload), len(payload)))
        self.assertGreaterEqual(len(events), 3)

    def test_declared_fixity_checks_all_available_required_hashes(self) -> None:
        ia_file = IAFile(
            name="sample.bin",
            sha1="1" * 40,
            md5="2" * 32,
            crc32="33333333",
        )

        with self.assertRaises(IAChecksumMismatch) as raised:
            verify_declared_fixity(
                identifier="fake-software-item",
                ia_file=ia_file,
                hashes={
                    "sha1": "1" * 40,
                    "md5": "9" * 32,
                    "crc32": "33333333",
                },
            )

        self.assertEqual(raised.exception.algorithm, "md5")

    def test_ingest_downloads_hashes_inserts_and_scans_zip(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"ia-ufid-{uuid.uuid4().hex}.sqlite"
        state_path = SCRATCH / f"ia-state-{uuid.uuid4().hex}.sqlite"
        cache_path = SCRATCH / f"ia-cache-{uuid.uuid4().hex}"
        runner = IAIngestRunner(
            options(db_path, state_path, cache_path),
            client=FakeIAClient(zip_payload()),
        )
        try:
            with redirect_stdout(StringIO()):
                stats = runner.run()
        finally:
            runner.close()

        with closing(connect(db_path)) as connection:
            files = list_files(connection)
        archive = next(item for item in files if item["display_name"] == "archive.zip")
        self.assertEqual(stats.processed_files, 1)
        self.assertEqual(stats.archive_members, 1)
        self.assertEqual(archive["archive_members"][0]["archive_path"], "inner/readme.txt")

    def test_metadata_mode_queues_and_inserts_complete_ia_identity(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"ia-ufid-metadata-{uuid.uuid4().hex}.sqlite"
        state_path = SCRATCH / f"ia-state-metadata-{uuid.uuid4().hex}.sqlite"
        cache_path = SCRATCH / f"ia-cache-metadata-{uuid.uuid4().hex}"
        payload = zip_payload()
        opts = options(db_path, state_path, cache_path)
        opts = IngestOptions(**{**opts.__dict__, "mode": "metadata"})
        client = FakeIAClient(payload)
        runner = IAIngestRunner(opts, client=client)
        try:
            with redirect_stdout(StringIO()):
                stats = runner.run()
        finally:
            runner.close()

        with closing(connect(db_path)) as connection:
            files = list_files(connection)
        state = IAIngestState(state_path)
        try:
            queued = state.iter_processable_files(retry_failed=False)
            item = state.get_item("fake-software-item")
        finally:
            state.close()

        self.assertEqual(stats.processed_items, 1)
        self.assertEqual(client.download_calls, 0)
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0]["display_name"], "archive.zip")
        self.assertEqual(files[0]["hashes"]["md5"], hashlib.md5(payload).hexdigest())
        self.assertEqual(len(queued), 1)
        self.assertEqual(queued[0].status, "pending")
        self.assertEqual(queued[0].ufid_file_id, files[0]["id"])
        self.assertFalse(queued[0].needs_downloaded_identity)
        self.assertEqual(queued[0].identity_metadata_status, "complete")
        self.assertEqual(queued[0].identity_metadata_missing, ())
        self.assertIsNotNone(item)
        assert item is not None
        self.assertEqual(item.status, "metadata_done")

    def test_metadata_mode_adds_unpromoted_ia_metadata_to_ufid(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"ia-ufid-extra-metadata-{uuid.uuid4().hex}.sqlite"
        state_path = SCRATCH / f"ia-state-extra-metadata-{uuid.uuid4().hex}.sqlite"
        cache_path = SCRATCH / f"ia-cache-extra-metadata-{uuid.uuid4().hex}"
        opts = options(db_path, state_path, cache_path)
        opts = IngestOptions(**{**opts.__dict__, "mode": "metadata"})
        client = FakeIAClient(
            zip_payload(),
            extra_top_level_metadata={
                "item_size": 2048,
                "workable_servers": [
                    "ia600000.us.archive.org",
                    "ia800000.us.archive.org",
                ],
                "reviews": [{"reviewtitle": "Useful"}],
                "is_dark": False,
            },
            extra_item_metadata={
                "creator": "Acme",
                "subject": ["software", "games"],
                "licenseurl": "https://example.test/license",
            },
            extra_file_metadata={
                "btih": "abc123",
                "viruscheck": "clean",
                "word_conf_91_100": 4,
            },
        )
        runner = IAIngestRunner(opts, client=client)
        try:
            with redirect_stdout(StringIO()):
                runner.run()
        finally:
            runner.close()

        with closing(connect(db_path)) as connection:
            files = list_files(connection)
        self.assertEqual(len(files), 1)
        file_record = files[0]
        self.assertEqual(metadata_values(file_record, "org.archive-creator"), ["Acme"])
        self.assertEqual(
            set(metadata_values(file_record, "org.archive-subject")),
            {"software", "games"},
        )
        self.assertEqual(metadata_values(file_record, "org.archive-item_size"), ["2048"])
        self.assertEqual(
            metadata_values(file_record, "org.archive-workable_servers"),
            ["ia600000.us.archive.org", "ia800000.us.archive.org"],
        )
        self.assertEqual(
            metadata_values(file_record, "org.archive-reviews"),
            [
                json.dumps(
                    [{"reviewtitle": "Useful"}],
                    separators=(",", ":"),
                    sort_keys=True,
                )
            ],
        )
        self.assertEqual(metadata_values(file_record, "org.archive-is_dark"), ["false"])
        self.assertEqual(metadata_values(file_record, "org.archive-btih"), ["abc123"])
        self.assertEqual(
            metadata_values(file_record, "org.archive-viruscheck"),
            ["clean"],
        )
        self.assertEqual(
            metadata_values(file_record, "org.archive-word_conf_91_100"),
            ["4"],
        )
        self.assertEqual(metadata_values(file_record, "org.archive-md5"), [])

    def test_downloaded_identity_keeps_unpromoted_ia_metadata(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"ia-ufid-download-extra-metadata-{uuid.uuid4().hex}.sqlite"
        state_path = SCRATCH / f"ia-state-download-extra-metadata-{uuid.uuid4().hex}.sqlite"
        cache_path = SCRATCH / f"ia-cache-download-extra-metadata-{uuid.uuid4().hex}"
        client = FakeIAClient(
            zip_payload(),
            omit_file_fields=("sha1",),
            extra_item_metadata={"creator": "Download Creator"},
            extra_file_metadata={"btih": "download-btih"},
        )
        runner = IAIngestRunner(options(db_path, state_path, cache_path), client=client)
        try:
            with redirect_stdout(StringIO()):
                stats = runner.run()
        finally:
            runner.close()

        with closing(connect(db_path)) as connection:
            files = list_files(connection)
        self.assertEqual(stats.processed_files, 1)
        self.assertEqual(len(files), 2)
        archive = next(item for item in files if item["display_name"] == "archive.zip")
        self.assertEqual(
            metadata_values(archive, "org.archive-creator"),
            ["Download Creator"],
        )
        self.assertEqual(metadata_values(archive, "org.archive-btih"), ["download-btih"])
        self.assertEqual(metadata_values(archive, "org.archive-sha1"), [])

    def test_metadata_mode_skips_ia_artifacts_by_default(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"ia-ufid-artifact-skip-{uuid.uuid4().hex}.sqlite"
        state_path = SCRATCH / f"ia-state-artifact-skip-{uuid.uuid4().hex}.sqlite"
        cache_path = SCRATCH / f"ia-cache-artifact-skip-{uuid.uuid4().hex}"
        payload = zip_payload()
        artifact_records = (
            ia_file_record(
                "fake-software-item_files.xml",
                b"<files />",
                source="metadata",
                file_format="Metadata",
            ),
            ia_file_record(
                "fake-software-item_meta.sqlite",
                b"sqlite metadata",
                source="metadata",
                file_format="Metadata",
            ),
            ia_file_record(
                "fake-software-item_meta.xml",
                b"<metadata />",
                source="metadata",
                file_format="Metadata",
            ),
        )
        opts = options(db_path, state_path, cache_path)
        opts = IngestOptions(**{**opts.__dict__, "mode": "metadata"})
        client = FakeIAClient(payload, extra_file_records=artifact_records)
        runner = IAIngestRunner(opts, client=client)
        try:
            with redirect_stdout(StringIO()):
                stats = runner.run()
        finally:
            runner.close()

        with closing(connect(db_path)) as connection:
            files = list_files(connection)
        state = IAIngestState(state_path)
        try:
            queued = state.iter_processable_files(retry_failed=False)
        finally:
            state.close()

        self.assertEqual(stats.skipped_files, 3)
        self.assertEqual({file["display_name"] for file in files}, {"archive.zip"})
        self.assertEqual([file.name for file in queued], ["downloads/archive.zip"])

    def test_metadata_mode_includes_ia_artifacts_when_requested(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"ia-ufid-artifact-include-{uuid.uuid4().hex}.sqlite"
        state_path = SCRATCH / f"ia-state-artifact-include-{uuid.uuid4().hex}.sqlite"
        cache_path = SCRATCH / f"ia-cache-artifact-include-{uuid.uuid4().hex}"
        payload = zip_payload()
        artifact_record = ia_file_record(
            "fake-software-item_meta.xml",
            b"<metadata />",
            source="metadata",
            file_format="Metadata",
        )
        opts = options(db_path, state_path, cache_path)
        opts = IngestOptions(
            **{
                **opts.__dict__,
                "mode": "metadata",
                "ia_artifacts": True,
            }
        )
        client = FakeIAClient(payload, extra_file_records=(artifact_record,))
        runner = IAIngestRunner(opts, client=client)
        try:
            with redirect_stdout(StringIO()):
                stats = runner.run()
        finally:
            runner.close()

        with closing(connect(db_path)) as connection:
            files = list_files(connection)
        state = IAIngestState(state_path)
        try:
            queued = state.iter_processable_files(retry_failed=False)
        finally:
            state.close()

        self.assertEqual(stats.skipped_files, 0)
        self.assertEqual(
            {file["display_name"] for file in files},
            {"archive.zip", "fake-software-item_meta.xml"},
        )
        self.assertEqual(
            {file.name for file in queued},
            {"downloads/archive.zip", "fake-software-item_meta.xml"},
        )

    def test_metadata_mode_marks_files_that_need_downloaded_identity(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"ia-ufid-metadata-marker-{uuid.uuid4().hex}.sqlite"
        state_path = SCRATCH / f"ia-state-metadata-marker-{uuid.uuid4().hex}.sqlite"
        cache_path = SCRATCH / f"ia-cache-metadata-marker-{uuid.uuid4().hex}"
        opts = options(db_path, state_path, cache_path)
        opts = IngestOptions(**{**opts.__dict__, "mode": "metadata"})
        client = FakeIAClient(zip_payload(), omit_file_fields=("crc32", "sha1"))
        runner = IAIngestRunner(opts, client=client)
        try:
            with redirect_stdout(StringIO()):
                stats = runner.run()
        finally:
            runner.close()

        state = IAIngestState(state_path)
        try:
            queued = state.iter_processable_files(retry_failed=False)
        finally:
            state.close()

        self.assertEqual(stats.processed_items, 1)
        self.assertEqual(len(queued), 1)
        self.assertIsNone(queued[0].ufid_file_id)
        self.assertTrue(queued[0].needs_downloaded_identity)
        self.assertEqual(queued[0].identity_metadata_status, "incomplete")
        self.assertEqual(queued[0].identity_metadata_missing, ("crc32", "sha1"))

    def test_collection_discovery_scans_child_collection_items(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"ia-ufid-collection-{uuid.uuid4().hex}.sqlite"
        state_path = SCRATCH / f"ia-state-collection-{uuid.uuid4().hex}.sqlite"
        cache_path = SCRATCH / f"ia-cache-collection-{uuid.uuid4().hex}"
        opts = options(db_path, state_path, cache_path)
        opts = IngestOptions(
            **{
                **opts.__dict__,
                "mode": "metadata",
                "max_items": 10,
                "discover_collections": True,
                "max_collection_depth": 1,
            }
        )
        client = CollectionDiscoveryClient()
        runner = IAIngestRunner(opts, client=client)
        try:
            with redirect_stdout(StringIO()):
                stats = runner.run()
        finally:
            runner.close()

        with closing(connect(db_path)) as connection:
            files = list_files(connection)

        self.assertEqual(
            client.scrape_queries,
            [
                "collection:software",
                "collection:software-subcollection",
                "collection:software",
                "collection:software-subcollection",
            ],
        )
        self.assertEqual(
            client.metadata_identifiers,
            ["software-subcollection", "child-software-item"],
        )
        self.assertEqual(stats.processed_items, 2)
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0]["display_name"], "child.bin")
        self.assertEqual(files[0]["hashes"]["sha1"], hashlib.sha1(client.payload).hexdigest())

        state = IAIngestState(state_path)
        try:
            root = state.get_checkpoint("unit-test")
            root_alias = state.get_checkpoint("collection::software")
            child_collection = state.get_checkpoint("collection::software-subcollection")
        finally:
            state.close()

        self.assertIsNotNone(root)
        self.assertIsNotNone(root_alias)
        self.assertIsNotNone(child_collection)
        assert root is not None
        assert root_alias is not None
        assert child_collection is not None
        self.assertEqual(root.imported_item_count, 1)
        self.assertEqual(root_alias.imported_item_count, 1)
        self.assertEqual(child_collection.imported_item_count, 1)

    def test_completed_item_and_unchanged_collection_state_only_rechecks_counts(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"ia-ufid-collection-repeat-{uuid.uuid4().hex}.sqlite"
        state_path = SCRATCH / f"ia-state-collection-repeat-{uuid.uuid4().hex}.sqlite"
        cache_path = SCRATCH / f"ia-cache-collection-repeat-{uuid.uuid4().hex}"
        opts = options(db_path, state_path, cache_path)
        opts = IngestOptions(
            **{
                **opts.__dict__,
                "mode": "metadata",
                "max_items": 10,
                "discover_collections": True,
                "max_collection_depth": 1,
            }
        )
        first_runner = IAIngestRunner(opts, client=CollectionDiscoveryClient())
        try:
            with redirect_stdout(StringIO()):
                first_runner.run()
        finally:
            first_runner.close()

        no_growth_client = CollectionNoGrowthClient()
        second_runner = IAIngestRunner(opts, client=no_growth_client)
        try:
            with redirect_stdout(StringIO()):
                second_runner.run()
        finally:
            second_runner.close()

        self.assertEqual(
            no_growth_client.scrape_queries,
            ["collection:software", "collection:software-subcollection"],
        )
        self.assertEqual(no_growth_client.metadata_calls, 0)
        self.assertEqual(no_growth_client.download_calls, 0)

    def test_collection_growth_reopens_collection_and_imports_new_items(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"ia-ufid-collection-growth-{uuid.uuid4().hex}.sqlite"
        state_path = SCRATCH / f"ia-state-collection-growth-{uuid.uuid4().hex}.sqlite"
        cache_path = SCRATCH / f"ia-cache-collection-growth-{uuid.uuid4().hex}"
        opts = options(db_path, state_path, cache_path)
        opts = IngestOptions(
            **{
                **opts.__dict__,
                "mode": "metadata",
                "max_items": 10,
                "discover_collections": True,
                "max_collection_depth": 1,
            }
        )
        first_runner = IAIngestRunner(opts, client=CollectionDiscoveryClient())
        try:
            with redirect_stdout(StringIO()):
                first_runner.run()
        finally:
            first_runner.close()

        growth_client = CollectionGrowthClient()
        second_runner = IAIngestRunner(opts, client=growth_client)
        try:
            with redirect_stdout(StringIO()):
                second_runner.run()
        finally:
            second_runner.close()

        with closing(connect(db_path)) as connection:
            files = list_files(connection)
        state = IAIngestState(state_path)
        try:
            child_collection = state.get_checkpoint("collection::software-subcollection")
        finally:
            state.close()

        self.assertEqual(
            growth_client.scrape_queries,
            [
                "collection:software",
                "collection:software-subcollection",
            ],
        )
        self.assertEqual(growth_client.metadata_calls, 1)
        self.assertEqual({file["display_name"] for file in files}, {"child.bin", "new-child.bin"})
        self.assertIsNotNone(child_collection)
        assert child_collection is not None
        self.assertEqual(child_collection.imported_item_count, 2)

    def test_debug_metadata_mode_prints_declared_api_hashes(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"ia-ufid-debug-{uuid.uuid4().hex}.sqlite"
        state_path = SCRATCH / f"ia-state-debug-{uuid.uuid4().hex}.sqlite"
        cache_path = SCRATCH / f"ia-cache-debug-{uuid.uuid4().hex}"
        payload = zip_payload()
        opts = options(db_path, state_path, cache_path)
        opts = IngestOptions(
            **{
                **opts.__dict__,
                "mode": "metadata",
                "quiet": False,
                "debug": True,
            }
        )
        client = FakeIAClient(payload)
        runner = IAIngestRunner(opts, client=client)
        output = StringIO()
        try:
            with redirect_stdout(output):
                runner.run()
        finally:
            runner.close()

        text = output.getvalue()
        self.assertIn("[debug] Captured IA metadata for item fake-software-item", text)
        self.assertIn(
            "[debug] IA API identity decision for fake-software-item/downloads/archive.zip",
            text,
        )
        self.assertIn("enough_data=yes", text)
        self.assertIn("added_to_database=yes", text)
        self.assertIn(f"ufid_target=sqlite:{db_path.resolve()}", text)
        self.assertIn(f"md5={hashlib.md5(payload).hexdigest()}", text)
        self.assertIn(f"sha1={hashlib.sha1(payload).hexdigest()}", text)
        self.assertIn("status=created", text)

    def test_debug_metadata_mode_prints_missing_identity_decision(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"ia-ufid-debug-missing-{uuid.uuid4().hex}.sqlite"
        state_path = SCRATCH / f"ia-state-debug-missing-{uuid.uuid4().hex}.sqlite"
        cache_path = SCRATCH / f"ia-cache-debug-missing-{uuid.uuid4().hex}"
        opts = options(db_path, state_path, cache_path)
        opts = IngestOptions(
            **{
                **opts.__dict__,
                "mode": "metadata",
                "quiet": False,
                "debug": True,
            }
        )
        runner = IAIngestRunner(
            opts,
            client=FakeIAClient(zip_payload(), omit_file_fields=("crc32", "sha1")),
        )
        output = StringIO()
        try:
            with redirect_stdout(output):
                runner.run()
        finally:
            runner.close()

        text = output.getvalue()
        self.assertIn("enough_data=no", text)
        self.assertIn("added_to_database=no", text)
        self.assertIn("crc32=<missing>", text)
        self.assertIn("sha1=<missing>", text)
        self.assertIn("missing=crc32,sha1", text)
        self.assertIn("status=needs-download", text)

    def test_download_mode_skips_non_archive_when_api_identity_already_stored(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"ia-ufid-skip-download-{uuid.uuid4().hex}.sqlite"
        state_path = SCRATCH / f"ia-state-skip-download-{uuid.uuid4().hex}.sqlite"
        cache_path = SCRATCH / f"ia-cache-skip-download-{uuid.uuid4().hex}"
        payload = b"plain non archive payload"
        metadata_opts = IngestOptions(
            **{**options(db_path, state_path, cache_path).__dict__, "mode": "metadata"}
        )
        metadata_runner = IAIngestRunner(
            metadata_opts,
            client=FakeIAClient(
                payload,
                file_name="downloads/plain.txt",
                file_format="Text",
            ),
        )
        try:
            with redirect_stdout(StringIO()):
                metadata_runner.run()
        finally:
            metadata_runner.close()

        download_client = FakeIAClient(
            payload,
            file_name="downloads/plain.txt",
            file_format="Text",
            fail_metadata=True,
            fail_scrape=True,
        )
        download_opts = IngestOptions(
            **{**options(db_path, state_path, cache_path).__dict__, "mode": "download"}
        )
        download_runner = IAIngestRunner(download_opts, client=download_client)
        try:
            with redirect_stdout(StringIO()):
                stats = download_runner.run()
        finally:
            download_runner.close()

        state = IAIngestState(state_path)
        try:
            queued = state.iter_processable_files(retry_failed=False)
            current = state.get_file("fake-software-item", "downloads/plain.txt")
        finally:
            state.close()

        self.assertEqual(download_client.download_calls, 0)
        self.assertEqual(stats.processed_files, 0)
        self.assertEqual(stats.skipped_files, 1)
        self.assertEqual(queued, [])
        self.assertIsNotNone(current)
        assert current is not None
        self.assertEqual(current.status, "done")

    def test_download_mode_does_not_archive_scan_complete_single_file_gzip(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"ia-ufid-skip-gzip-{uuid.uuid4().hex}.sqlite"
        state_path = SCRATCH / f"ia-state-skip-gzip-{uuid.uuid4().hex}.sqlite"
        cache_path = SCRATCH / f"ia-cache-skip-gzip-{uuid.uuid4().hex}"
        payload = gzip.compress(b"ocr derivative text")
        file_name = "downloads/page_hocr.html.gz"
        metadata_opts = IngestOptions(
            **{**options(db_path, state_path, cache_path).__dict__, "mode": "metadata"}
        )
        metadata_runner = IAIngestRunner(
            metadata_opts,
            client=FakeIAClient(
                payload,
                file_name=file_name,
                file_format="GZIP",
            ),
        )
        try:
            with redirect_stdout(StringIO()):
                metadata_runner.run()
        finally:
            metadata_runner.close()

        download_client = FakeIAClient(
            payload,
            file_name=file_name,
            file_format="GZIP",
            fail_metadata=True,
            fail_scrape=True,
        )
        download_opts = IngestOptions(
            **{**options(db_path, state_path, cache_path).__dict__, "mode": "download"}
        )
        download_runner = IAIngestRunner(download_opts, client=download_client)
        try:
            with redirect_stdout(StringIO()):
                stats = download_runner.run()
        finally:
            download_runner.close()

        state = IAIngestState(state_path)
        try:
            queued = state.iter_processable_files(retry_failed=False)
            current = state.get_file("fake-software-item", file_name)
        finally:
            state.close()

        self.assertEqual(download_client.download_calls, 0)
        self.assertEqual(stats.processed_files, 0)
        self.assertEqual(stats.skipped_files, 1)
        self.assertEqual(queued, [])
        self.assertIsNotNone(current)
        assert current is not None
        self.assertEqual(current.status, "done")

    def test_download_mode_defers_incomplete_single_file_gzip_by_default(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"ia-ufid-defer-gzip-{uuid.uuid4().hex}.sqlite"
        state_path = SCRATCH / f"ia-state-defer-gzip-{uuid.uuid4().hex}.sqlite"
        cache_path = SCRATCH / f"ia-cache-defer-gzip-{uuid.uuid4().hex}"
        payload = gzip.compress(b"ocr derivative text")
        file_name = "downloads/page_hocr.html.gz"
        metadata_opts = IngestOptions(
            **{**options(db_path, state_path, cache_path).__dict__, "mode": "metadata"}
        )
        metadata_runner = IAIngestRunner(
            metadata_opts,
            client=FakeIAClient(
                payload,
                omit_file_fields=("crc32", "sha1"),
                file_name=file_name,
                file_format="GZIP",
            ),
        )
        try:
            with redirect_stdout(StringIO()):
                metadata_runner.run()
        finally:
            metadata_runner.close()

        download_client = FakeIAClient(
            payload,
            omit_file_fields=("crc32", "sha1"),
            file_name=file_name,
            file_format="GZIP",
            fail_metadata=True,
            fail_scrape=True,
        )
        download_opts = IngestOptions(
            **{**options(db_path, state_path, cache_path).__dict__, "mode": "download"}
        )
        download_runner = IAIngestRunner(download_opts, client=download_client)
        try:
            with redirect_stdout(StringIO()):
                stats = download_runner.run()
        finally:
            download_runner.close()

        state = IAIngestState(state_path)
        try:
            queued = state.iter_processable_files(retry_failed=False)
            current = state.get_file("fake-software-item", file_name)
        finally:
            state.close()

        self.assertEqual(download_client.download_calls, 0)
        self.assertEqual(stats.processed_files, 0)
        self.assertEqual(stats.skipped_files, 1)
        self.assertEqual(len(queued), 1)
        self.assertIsNotNone(current)
        assert current is not None
        self.assertEqual(current.status, "pending")

    def test_download_mode_defers_non_archive_missing_identity_by_default(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"ia-ufid-defer-plain-{uuid.uuid4().hex}.sqlite"
        state_path = SCRATCH / f"ia-state-defer-plain-{uuid.uuid4().hex}.sqlite"
        cache_path = SCRATCH / f"ia-cache-defer-plain-{uuid.uuid4().hex}"
        payload = b"plain payload without complete IA identity"
        metadata_opts = IngestOptions(
            **{**options(db_path, state_path, cache_path).__dict__, "mode": "metadata"}
        )
        metadata_runner = IAIngestRunner(
            metadata_opts,
            client=FakeIAClient(
                payload,
                omit_file_fields=("crc32", "sha1"),
                file_name="downloads/plain.txt",
                file_format="Text",
            ),
        )
        try:
            with redirect_stdout(StringIO()):
                metadata_runner.run()
        finally:
            metadata_runner.close()

        download_client = FakeIAClient(
            payload,
            omit_file_fields=("crc32", "sha1"),
            file_name="downloads/plain.txt",
            file_format="Text",
            fail_metadata=True,
            fail_scrape=True,
        )
        download_opts = IngestOptions(
            **{**options(db_path, state_path, cache_path).__dict__, "mode": "download"}
        )
        download_runner = IAIngestRunner(download_opts, client=download_client)
        try:
            with redirect_stdout(StringIO()):
                stats = download_runner.run()
        finally:
            download_runner.close()

        state = IAIngestState(state_path)
        try:
            queued = state.iter_processable_files(retry_failed=False)
            current = state.get_file("fake-software-item", "downloads/plain.txt")
        finally:
            state.close()

        self.assertEqual(download_client.download_calls, 0)
        self.assertEqual(stats.processed_files, 0)
        self.assertEqual(stats.skipped_files, 1)
        self.assertEqual(len(queued), 1)
        self.assertIsNotNone(current)
        assert current is not None
        self.assertEqual(current.status, "pending")

        deep_client = FakeIAClient(
            payload,
            omit_file_fields=("crc32", "sha1"),
            file_name="downloads/plain.txt",
            file_format="Text",
            fail_metadata=True,
            fail_scrape=True,
        )
        deep_opts = IngestOptions(
            **{
                **options(db_path, state_path, cache_path).__dict__,
                "mode": "download",
                "deep_discover_archives": True,
            }
        )
        deep_runner = IAIngestRunner(deep_opts, client=deep_client)
        try:
            with redirect_stdout(StringIO()):
                deep_stats = deep_runner.run()
        finally:
            deep_runner.close()

        with closing(connect(db_path)) as connection:
            files = list_files(connection)
        self.assertEqual(deep_client.download_calls, 1)
        self.assertEqual(deep_stats.processed_files, 1)
        self.assertEqual(files[0]["display_name"], "plain.txt")

    def test_download_mode_max_size_defers_queue_without_marking_skipped(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"ia-ufid-max-size-{uuid.uuid4().hex}.sqlite"
        state_path = SCRATCH / f"ia-state-max-size-{uuid.uuid4().hex}.sqlite"
        cache_path = SCRATCH / f"ia-cache-max-size-{uuid.uuid4().hex}"
        payload = zip_payload()
        metadata_opts = IngestOptions(
            **{**options(db_path, state_path, cache_path).__dict__, "mode": "metadata"}
        )
        metadata_runner = IAIngestRunner(metadata_opts, client=FakeIAClient(payload))
        try:
            with redirect_stdout(StringIO()):
                metadata_runner.run()
        finally:
            metadata_runner.close()

        download_client = FakeIAClient(payload, fail_metadata=True, fail_scrape=True)
        download_opts = IngestOptions(
            **{
                **options(db_path, state_path, cache_path).__dict__,
                "mode": "download",
                "max_size_bytes": len(payload) - 1,
            }
        )
        download_runner = IAIngestRunner(download_opts, client=download_client)
        try:
            with redirect_stdout(StringIO()):
                stats = download_runner.run()
        finally:
            download_runner.close()

        state = IAIngestState(state_path)
        try:
            queued = state.iter_processable_files(retry_failed=False)
            current = state.get_file("fake-software-item", "downloads/archive.zip")
        finally:
            state.close()

        self.assertEqual(download_client.download_calls, 0)
        self.assertEqual(stats.processed_files, 0)
        self.assertEqual(stats.skipped_files, 1)
        self.assertEqual(len(queued), 1)
        self.assertIsNotNone(current)
        assert current is not None
        self.assertEqual(current.status, "pending")

    def test_download_mode_min_size_defers_queue_without_marking_skipped(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"ia-ufid-min-size-{uuid.uuid4().hex}.sqlite"
        state_path = SCRATCH / f"ia-state-min-size-{uuid.uuid4().hex}.sqlite"
        cache_path = SCRATCH / f"ia-cache-min-size-{uuid.uuid4().hex}"
        payload = zip_payload()
        metadata_opts = IngestOptions(
            **{**options(db_path, state_path, cache_path).__dict__, "mode": "metadata"}
        )
        metadata_runner = IAIngestRunner(metadata_opts, client=FakeIAClient(payload))
        try:
            with redirect_stdout(StringIO()):
                metadata_runner.run()
        finally:
            metadata_runner.close()

        download_client = FakeIAClient(payload, fail_metadata=True, fail_scrape=True)
        download_opts = IngestOptions(
            **{
                **options(db_path, state_path, cache_path).__dict__,
                "mode": "download",
                "min_size_bytes": len(payload) + 1,
            }
        )
        download_runner = IAIngestRunner(download_opts, client=download_client)
        try:
            with redirect_stdout(StringIO()):
                stats = download_runner.run()
        finally:
            download_runner.close()

        state = IAIngestState(state_path)
        try:
            queued = state.iter_processable_files(retry_failed=False)
            current = state.get_file("fake-software-item", "downloads/archive.zip")
        finally:
            state.close()

        self.assertEqual(download_client.download_calls, 0)
        self.assertEqual(stats.processed_files, 0)
        self.assertEqual(stats.skipped_files, 1)
        self.assertEqual(len(queued), 1)
        self.assertIsNotNone(current)
        assert current is not None
        self.assertEqual(current.status, "pending")

    def test_download_mode_processes_existing_queue_without_scrape_or_metadata(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"ia-ufid-download-{uuid.uuid4().hex}.sqlite"
        state_path = SCRATCH / f"ia-state-download-{uuid.uuid4().hex}.sqlite"
        cache_path = SCRATCH / f"ia-cache-download-{uuid.uuid4().hex}"
        payload = zip_payload()
        metadata_opts = IngestOptions(**{**options(db_path, state_path, cache_path).__dict__, "mode": "metadata"})
        metadata_runner = IAIngestRunner(
            metadata_opts,
            client=FakeIAClient(payload),
        )
        try:
            with redirect_stdout(StringIO()):
                metadata_runner.run()
        finally:
            metadata_runner.close()

        download_client = FakeIAClient(
            payload,
            fail_metadata=True,
            fail_scrape=True,
        )
        download_opts = IngestOptions(**{**options(db_path, state_path, cache_path).__dict__, "mode": "download"})
        download_runner = IAIngestRunner(download_opts, client=download_client)
        try:
            with redirect_stdout(StringIO()):
                stats = download_runner.run()
        finally:
            download_runner.close()

        with closing(connect(db_path)) as connection:
            files = list_files(connection)
        archive = next(item for item in files if item["display_name"] == "archive.zip")
        self.assertEqual(stats.processed_files, 1)
        self.assertEqual(download_client.download_calls, 1)
        self.assertEqual(archive["archive_members"][0]["archive_path"], "inner/readme.txt")

    def test_declared_checksum_mismatch_keeps_metadata_identity_and_fails_download(self) -> None:
        SCRATCH.mkdir(exist_ok=True)
        db_path = SCRATCH / f"ia-ufid-mismatch-{uuid.uuid4().hex}.sqlite"
        state_path = SCRATCH / f"ia-state-mismatch-{uuid.uuid4().hex}.sqlite"
        cache_path = SCRATCH / f"ia-cache-mismatch-{uuid.uuid4().hex}"
        runner = IAIngestRunner(
            options(db_path, state_path, cache_path),
            client=FakeIAClient(zip_payload(), declared_sha1="0" * 40),
        )
        try:
            with redirect_stdout(StringIO()):
                stats = runner.run()
        finally:
            runner.close()

        with closing(connect(db_path)) as connection:
            files = list_files(connection)
        self.assertEqual(stats.failed_files, 1)
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0]["display_name"], "archive.zip")
        self.assertEqual(files[0]["hashes"]["sha1"], "0" * 40)


if __name__ == "__main__":
    unittest.main()
