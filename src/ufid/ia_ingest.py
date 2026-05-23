from __future__ import annotations

import argparse
from abc import ABC, abstractmethod
from dataclasses import dataclass
import json
import logging
import mimetypes
import os
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any, Mapping

from ufid import api_client
from ufid.add import (
    ArchiveScanResult,
    add_archive_contents_to_backend,
    add_archive_contents_to_local,
)
from ufid.archives import (
    looks_like_archive_path,
    looks_like_single_file_compression_path,
    looks_like_supported_archive_container_path,
)
from ufid.database import (
    IdentityConflict,
    add_file_metadata,
    connect,
    upsert_file_identity,
)
from ufid.hashing import DEFAULT_ALGORITHMS, SUPPORTED_ALGORITHMS, compute_file_hashes
from ufid.ia_client import (
    DEFAULT_USER_AGENT,
    IAClientError,
    IAFile,
    IAHTTPClient,
    file_url,
    is_ia_artifact_file,
    parse_item_metadata,
    safe_download_path,
    verify_declared_fixity,
)
from ufid.ia_state import IAIngestState, QueuedFile
from ufid.paths import (
    default_ia_cache_dir,
    default_ia_state_db_path,
    default_sqlite_db_path,
)


LOGGER = logging.getLogger(__name__)

DEFAULT_COLLECTION = "vintagesoftware"
INGEST_MODES = ("all", "metadata", "download")
DEFAULT_SCRAPE_FIELDS = ["identifier", "title", "mediatype", "collection"]
REQUIRED_IA_IDENTITY_FIELDS = ("size", "crc32", "md5", "sha1")
IA_METADATA_PREFIX = "org.archive-"
IA_ARTIFACT_TAG = "IA Artefacts"
IA_SOURCE_VALUE = "internet_archive"
IA_ITEM_CONTAINER_FIELDS = {"metadata", "files"}
PROMOTED_IA_FILE_FIELDS = {
    "name",
    "source",
    "format",
    "size",
    "mtime",
    "md5",
    "sha1",
    "crc32",
    "url",
}
UNSUPPORTED_CONTAINER_SUFFIXES = (
    ".iso",
    ".isz",
    ".7z",
    ".rar",
    ".cab",
    ".dmg",
    ".img",
    ".chd",
    ".vhd",
    ".vhdx",
    ".hfs",
)


@dataclass
class IngestStats:
    discovered_items: int = 0
    processed_items: int = 0
    skipped_items: int = 0
    failed_items: int = 0
    processed_files: int = 0
    skipped_files: int = 0
    failed_files: int = 0
    ufid_created: int = 0
    ufid_enriched: int = 0
    archive_members: int = 0
    archive_errors: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "discovered_items": self.discovered_items,
            "processed_items": self.processed_items,
            "skipped_items": self.skipped_items,
            "failed_items": self.failed_items,
            "processed_files": self.processed_files,
            "skipped_files": self.skipped_files,
            "failed_files": self.failed_files,
            "ufid_created": self.ufid_created,
            "ufid_enriched": self.ufid_enriched,
            "archive_members": self.archive_members,
            "archive_errors": self.archive_errors,
        }


@dataclass(frozen=True)
class CollectionCandidate:
    identifier: str
    depth: int
    query: str
    crawl_key: str


@dataclass(frozen=True)
class IngestOptions:
    mode: str
    query: str
    crawl_key: str
    backend: str | None
    api_token: str | None
    db_path: str
    state_db: str
    cache_dir: Path
    user_agent: str
    algorithms: tuple[str, ...]
    scrape_count: int
    timeout: float
    max_retries: int
    request_delay_seconds: float
    download_delay_seconds: float
    max_items: int | None
    max_files: int | None
    max_file_bytes: int | None
    min_size_bytes: int | None
    max_size_bytes: int | None
    original_only: bool
    keep_cache: bool
    retry_failed: bool
    dry_run: bool
    no_archive_scan: bool
    deep_discover_archives: bool
    allow_checksum_mismatch: bool
    discover_collections: bool
    max_collection_depth: int
    max_collections: int | None
    jsonl: bool
    quiet: bool
    debug: bool


class UFIDTarget(ABC):
    @abstractmethod
    def upsert_declared_file(
        self,
        *,
        identifier: str,
        ia_file: IAFile,
        item_metadata: Mapping[str, Any] | None,
        hashes: Mapping[str, str],
        size_bytes: int,
    ) -> tuple[int, bool, bool]:
        """Create or enrich a UFID record from IA-declared identity metadata."""

    @abstractmethod
    def upsert_downloaded_file(
        self,
        *,
        identifier: str,
        ia_file: IAFile,
        item_metadata: Mapping[str, Any] | None,
        local_path: Path,
        hashes: Mapping[str, str],
        size_bytes: int,
    ) -> tuple[int, bool, bool]:
        """Create or enrich a UFID record from a downloaded file."""

    @abstractmethod
    def add_metadata(
        self,
        file_id: int,
        metadata: list[Mapping[str, Any]],
    ) -> None:
        """Append metadata rows to an existing UFID record."""

    @abstractmethod
    def scan_archive(
        self,
        *,
        archive_path: Path,
        parent_file_id: int,
        algorithms: tuple[str, ...],
    ) -> ArchiveScanResult:
        """Inspect archive contents and attach discovered members."""

    def close(self) -> None:
        return


class LocalUFIDTarget(UFIDTarget):
    def __init__(self, db_path: str) -> None:
        self.connection = connect(db_path)

    def upsert_declared_file(
        self,
        *,
        identifier: str,
        ia_file: IAFile,
        item_metadata: Mapping[str, Any] | None,
        hashes: Mapping[str, str],
        size_bytes: int,
    ) -> tuple[int, bool, bool]:
        result = upsert_file_identity(
            self.connection,
            display_name=PurePosixPath(ia_file.name).name or ia_file.name,
            size_bytes=size_bytes,
            hashes=hashes,
            description=f"Internet Archive file {identifier}/{ia_file.name}",
            content_type=mimetypes.guess_type(ia_file.name)[0],
            metadata=ia_metadata(identifier, ia_file, item_metadata=item_metadata),
        )
        return result.file_id, result.created, result.enriched

    def upsert_downloaded_file(
        self,
        *,
        identifier: str,
        ia_file: IAFile,
        item_metadata: Mapping[str, Any] | None,
        local_path: Path,
        hashes: Mapping[str, str],
        size_bytes: int,
    ) -> tuple[int, bool, bool]:
        result = upsert_file_identity(
            self.connection,
            display_name=PurePosixPath(ia_file.name).name or ia_file.name,
            size_bytes=size_bytes,
            hashes=hashes,
            description=f"Internet Archive file {identifier}/{ia_file.name}",
            content_type=mimetypes.guess_type(ia_file.name)[0],
            metadata=ia_metadata(identifier, ia_file, item_metadata=item_metadata),
        )
        return result.file_id, result.created, result.enriched

    def add_metadata(
        self,
        file_id: int,
        metadata: list[Mapping[str, Any]],
    ) -> None:
        add_file_metadata(self.connection, file_id=file_id, metadata=metadata)

    def scan_archive(
        self,
        *,
        archive_path: Path,
        parent_file_id: int,
        algorithms: tuple[str, ...],
    ) -> ArchiveScanResult:
        return add_archive_contents_to_local(
            connection=self.connection,
            archive_path=archive_path,
            parent_file_id=parent_file_id,
            algorithms=algorithms,
        )

    def close(self) -> None:
        self.connection.close()


class BackendUFIDTarget(UFIDTarget):
    def __init__(self, backend: str, *, api_token: str | None = None) -> None:
        self.backend = backend
        self.api_token = api_token

    def upsert_declared_file(
        self,
        *,
        identifier: str,
        ia_file: IAFile,
        item_metadata: Mapping[str, Any] | None,
        hashes: Mapping[str, str],
        size_bytes: int,
    ) -> tuple[int, bool, bool]:
        response = api_client.upsert_file(
            self.backend,
            {
                "display_name": PurePosixPath(ia_file.name).name or ia_file.name,
                "size_bytes": size_bytes,
                "description": f"Internet Archive file {identifier}/{ia_file.name}",
                "content_type": mimetypes.guess_type(ia_file.name)[0],
                "hashes": dict(hashes),
                "metadata": ia_metadata(
                    identifier,
                    ia_file,
                    item_metadata=item_metadata,
                ),
            },
            api_token=self.api_token,
        )
        return int(response["id"]), bool(response["created"]), bool(response["enriched"])

    def upsert_downloaded_file(
        self,
        *,
        identifier: str,
        ia_file: IAFile,
        item_metadata: Mapping[str, Any] | None,
        local_path: Path,
        hashes: Mapping[str, str],
        size_bytes: int,
    ) -> tuple[int, bool, bool]:
        response = api_client.upsert_file(
            self.backend,
            {
                "display_name": PurePosixPath(ia_file.name).name or ia_file.name,
                "size_bytes": size_bytes,
                "description": f"Internet Archive file {identifier}/{ia_file.name}",
                "content_type": mimetypes.guess_type(ia_file.name)[0],
                "hashes": dict(hashes),
                "metadata": ia_metadata(
                    identifier,
                    ia_file,
                    item_metadata=item_metadata,
                ),
            },
            api_token=self.api_token,
        )
        return int(response["id"]), bool(response["created"]), bool(response["enriched"])

    def add_metadata(
        self,
        file_id: int,
        metadata: list[Mapping[str, Any]],
    ) -> None:
        api_client.add_file_metadata(
            self.backend,
            file_id=file_id,
            metadata=metadata,
            api_token=self.api_token,
        )

    def scan_archive(
        self,
        *,
        archive_path: Path,
        parent_file_id: int,
        algorithms: tuple[str, ...],
    ) -> ArchiveScanResult:
        return add_archive_contents_to_backend(
            backend=self.backend,
            archive_path=archive_path,
            parent_file_id=parent_file_id,
            algorithms=algorithms,
            api_token=self.api_token,
        )


class IAIngestRunner:
    def __init__(
        self,
        options: IngestOptions,
        *,
        client: IAHTTPClient | None = None,
        state: IAIngestState | None = None,
        target: UFIDTarget | None = None,
    ) -> None:
        self.options = options
        self.client = client or IAHTTPClient(
            user_agent=options.user_agent,
            timeout=options.timeout,
            max_retries=options.max_retries,
            request_delay_seconds=options.request_delay_seconds,
            download_delay_seconds=options.download_delay_seconds,
        )
        self.state = state or IAIngestState(options.state_db)
        self.target = target or (
            BackendUFIDTarget(options.backend, api_token=options.api_token)
            if options.backend
            else LocalUFIDTarget(options.db_path)
        )
        self.stats = IngestStats()
        self._collections: dict[str, CollectionCandidate] = {}
        self._queued_collections: list[str] = []
        self._seen_collections: set[str] = set()
        self._rechecked_collection_keys: set[str] = set()
        self._scanned_collections = 0

    def close(self) -> None:
        self.target.close()
        self.state.close()

    def run(self) -> IngestStats:
        self.options.cache_dir.mkdir(parents=True, exist_ok=True)
        self._progress(
            "info",
            "target",
            "UFID ingest target",
            ufid_target=self._target_label(),
            state_db=str(Path(self.options.state_db).resolve()),
            cache=str(self.options.cache_dir.resolve()),
        )
        self._progress(
            "info",
            "source",
            "IA discovery source",
            query=self.options.query,
            crawl_key=self.options.crawl_key,
            collection_discovery=self.options.discover_collections,
            collection_depth=self.options.max_collection_depth,
        )
        if self.options.mode in {"all", "metadata"}:
            self._process_pending_items()
            self._scrape_and_process()
        if self.options.mode in {"all", "download"}:
            self._process_queued_files()
        self._progress("info", "summary", "IA ingest finished", stats=self.stats.as_dict())
        return self.stats

    def _process_pending_items(self) -> None:
        remaining = self._remaining_items()
        if remaining == 0:
            return
        pending = self.state.iter_processable_items(
            retry_failed=self.options.retry_failed,
            limit=remaining,
        )
        if pending:
            self._progress(
                "info",
                "resume",
                f"Processing {len(pending)} pending IA item(s) from state",
            )
        for item_state in pending:
            if self._remaining_items() == 0:
                break
            self._process_item(item_state.identifier)

    def _process_queued_files(self) -> None:
        remaining = self._remaining_files()
        if remaining == 0:
            return
        queued = self.state.iter_processable_files(
            retry_failed=self.options.retry_failed,
            limit=remaining,
        )
        self._progress(
            "info",
            "download_queue",
            f"Processing {len(queued)} queued IA file(s)",
        )
        for queued_file in queued:
            if self._remaining_files() == 0:
                break
            ia_file = queued_file_to_ia_file(queued_file)
            if self._should_skip_file(queued_file.item_identifier, ia_file):
                continue
            if not self._requires_download_analysis(queued_file, ia_file):
                assert queued_file.ufid_file_id is not None
                self.stats.skipped_files += 1
                self.state.mark_file_status(
                    queued_file.item_identifier,
                    queued_file.name,
                    "done",
                    ufid_file_id=queued_file.ufid_file_id,
                    error=None,
                )
                self._progress(
                    "info",
                    "download_not_needed",
                    (
                        "API identity already stored; no archive analysis needed for "
                        f"{queued_file.item_identifier}/{queued_file.name}"
                    ),
                    ufid_file_id=queued_file.ufid_file_id,
                )
                continue
            if self._should_defer_download(queued_file, ia_file):
                continue
            try:
                self._process_file(queued_file.item_identifier, ia_file, queued_file)
            except Exception as exc:
                self.stats.failed_files += 1
                self.state.mark_file_status(
                    queued_file.item_identifier,
                    queued_file.name,
                    "failed",
                    error=str(exc),
                    increment_attempts=True,
                )
                self.state.log_event(
                    "error",
                    f"File ingest failed: {exc}",
                    item_identifier=queued_file.item_identifier,
                    file_name=queued_file.name,
                )
                self._progress(
                    "error",
                    "file_failed",
                    f"File ingest failed for {queued_file.item_identifier}/{queued_file.name}: {exc}",
                )

    def _scrape_and_process(self) -> None:
        self._remember_root_collection()
        self._scrape_query(
            query=self.options.query,
            crawl_key=self.options.crawl_key,
            depth=0,
        )
        if not self.options.discover_collections:
            return

        self._queue_known_state_collections(depth=1)
        while True:
            self._process_collection_queue()
            if not self._recheck_collections_for_growth():
                break

    def _process_collection_queue(self) -> None:
        while self._queued_collections and self._remaining_items() != 0:
            if (
                self.options.max_collections is not None
                and self._scanned_collections >= self.options.max_collections
            ):
                self._progress(
                    "info",
                    "collection_limit",
                    "Collection discovery limit reached",
                    max_collections=self.options.max_collections,
                )
                break
            key = self._queued_collections.pop(0)
            candidate = self._collections.get(key)
            if candidate is None or candidate.depth > self.options.max_collection_depth:
                continue
            self._scanned_collections += 1
            self._progress(
                "info",
                "collection_scan",
                f"Scanning IA collection: {candidate.identifier}",
                query=candidate.query,
                depth=candidate.depth,
            )
            self._scrape_query(
                query=candidate.query,
                crawl_key=candidate.crawl_key,
                depth=candidate.depth,
            )

    def _scrape_query(
        self,
        *,
        query: str,
        crawl_key: str,
        depth: int,
        force_refresh: bool = False,
        initial_data: Mapping[str, Any] | None = None,
    ) -> None:
        checkpoint = self.state.get_checkpoint(crawl_key)
        cursor = (
            None
            if force_refresh
            else checkpoint.cursor if checkpoint and not checkpoint.completed else None
        )
        if checkpoint and checkpoint.completed and not force_refresh:
            self._progress(
                "info",
                "checkpoint",
                f"Crawl checkpoint is already complete for {crawl_key}",
                query=query,
            )
            return

        discovered_in_query = 0
        observed_total: int | None = None
        pending_data = initial_data
        while self._remaining_items() != 0:
            if pending_data is None:
                data = self.client.scrape(
                    query=query,
                    fields=DEFAULT_SCRAPE_FIELDS,
                    count=self.options.scrape_count,
                    cursor=cursor,
                )
            else:
                data = dict(pending_data)
                pending_data = None
            items = [item for item in data.get("items", []) if isinstance(item, dict)]
            next_cursor = data.get("cursor")
            page_total = _coerce_non_negative_int(data.get("total"))
            if page_total is not None:
                observed_total = page_total
            self._progress(
                "info",
                "scrape_page",
                f"Discovered {len(items)} IA item(s)",
                query=query,
                total=data.get("total"),
                count=data.get("count"),
            )
            for doc in items:
                identifier = str(doc.get("identifier") or "").strip()
                if not identifier:
                    continue
                self.state.upsert_discovered_item(
                    query=query,
                    identifier=identifier,
                    title=_optional_str(doc.get("title")),
                    mediatype=_optional_str(doc.get("mediatype")),
                )
                self.stats.discovered_items += 1
                discovered_in_query += 1
                self._queue_collection_from_doc(doc, depth=depth + 1)
                if self._remaining_items() == 0:
                    continue
                if self._item_metadata_already_scanned(identifier):
                    self.stats.skipped_items += 1
                    self._debug(
                        "metadata_cached",
                        f"Skipping already-scanned IA item: {identifier}",
                        query=query,
                    )
                    continue
                self._process_item(identifier)

            cursor = str(next_cursor) if next_cursor else None
            completed = cursor is None
            imported_item_count = (
                max(observed_total, discovered_in_query)
                if observed_total is not None
                else discovered_in_query if completed else None
            )
            self._save_checkpoint(
                crawl_key=crawl_key,
                query=query,
                cursor=cursor,
                completed=completed,
                imported_item_count=imported_item_count if completed else None,
            )
            if completed:
                break

    def _save_checkpoint(
        self,
        *,
        crawl_key: str,
        query: str,
        cursor: str | None,
        completed: bool,
        imported_item_count: int | None,
    ) -> None:
        self.state.save_checkpoint(
            crawl_key=crawl_key,
            query=query,
            cursor=cursor,
            completed=completed,
            imported_item_count=imported_item_count,
        )
        collection = collection_identifier_from_query(query)
        if collection is None:
            return
        alias = collection_crawl_key(self.options.crawl_key, collection)
        if alias == crawl_key:
            return
        self.state.save_checkpoint(
            crawl_key=alias,
            query=query,
            cursor=cursor,
            completed=completed,
            imported_item_count=imported_item_count,
        )

    def _remember_root_collection(self) -> None:
        collection = collection_identifier_from_query(self.options.query)
        if collection is None:
            return
        self._remember_collection(
            collection,
            depth=0,
            crawl_key=self.options.crawl_key,
        )

    def _remember_collection(
        self,
        identifier: str,
        *,
        depth: int,
        crawl_key: str | None = None,
    ) -> CollectionCandidate | None:
        collection = identifier.strip()
        if not collection:
            return None
        key = collection.lower()
        existing = self._collections.get(key)
        if existing and existing.depth <= depth:
            return existing
        candidate = CollectionCandidate(
            identifier=collection,
            depth=depth,
            query=collection_query(collection),
            crawl_key=crawl_key or collection_crawl_key(self.options.crawl_key, collection),
        )
        self._collections[key] = candidate
        return candidate

    def _recheck_collections_for_growth(self) -> bool:
        reopened = False
        for key, candidate in list(self._collections.items()):
            if key in self._rechecked_collection_keys:
                continue
            self._rechecked_collection_keys.add(key)
            if candidate.depth > self.options.max_collection_depth:
                continue
            checkpoint = self.state.get_checkpoint(candidate.crawl_key)
            if checkpoint is None or not checkpoint.completed:
                continue
            if self._remaining_items() == 0:
                break
            data = self.client.scrape(
                query=candidate.query,
                fields=DEFAULT_SCRAPE_FIELDS,
                count=self.options.scrape_count,
            )
            current_total = _coerce_non_negative_int(data.get("total"))
            if current_total is None:
                current_total = len(
                    [item for item in data.get("items", []) if isinstance(item, dict)]
                )
            stored_total = checkpoint.imported_item_count
            if stored_total is not None and current_total <= stored_total:
                self._debug(
                    "collection_unchanged",
                    f"IA collection has no new items: {candidate.identifier}",
                    previous_count=stored_total,
                    current_count=current_total,
                    query=candidate.query,
                )
                continue
            self._progress(
                "info",
                "collection_grew",
                f"IA collection will be refreshed: {candidate.identifier}",
                previous_count=stored_total if stored_total is not None else "unknown",
                current_count=current_total,
                query=candidate.query,
            )
            self._scrape_query(
                query=candidate.query,
                crawl_key=candidate.crawl_key,
                depth=candidate.depth,
                force_refresh=True,
                initial_data=data,
            )
            reopened = True
        return reopened

    def _queue_known_state_collections(self, *, depth: int) -> None:
        for identifier in self.state.iter_collection_item_identifiers():
            self._queue_collection(identifier, depth=depth)

    def _queue_collection_from_doc(self, doc: Mapping[str, Any], *, depth: int) -> None:
        if not self.options.discover_collections:
            return
        mediatype = str(doc.get("mediatype") or "").strip().lower()
        if mediatype != "collection":
            return
        identifier = str(doc.get("identifier") or "").strip()
        self._queue_collection(identifier, depth=depth)

    def _queue_collection(self, identifier: str, *, depth: int) -> None:
        candidate = self._remember_collection(identifier, depth=depth)
        if candidate is None or candidate.depth > self.options.max_collection_depth:
            return
        if candidate.query == self.options.query:
            return
        key = candidate.identifier.lower()
        if key in self._seen_collections:
            return
        self._seen_collections.add(key)
        checkpoint = self.state.get_checkpoint(candidate.crawl_key)
        if checkpoint and checkpoint.completed:
            self._debug(
                "collection_cached",
                f"Skipping already-scanned IA collection: {candidate.identifier}",
                query=candidate.query,
                checkpoint=checkpoint.crawl_key,
            )
            return
        self._queued_collections.append(key)
        self._debug(
            "collection_queued",
            f"Queued IA collection for discovery: {candidate.identifier}",
            depth=candidate.depth,
            query=candidate.query,
        )

    def _item_metadata_already_scanned(self, identifier: str) -> bool:
        if self.options.retry_failed:
            return False
        return self.state.item_metadata_already_scanned(identifier)

    def _process_item(self, identifier: str) -> None:
        item_state = self.state.get_item(identifier)
        if (
            item_state
            and item_state.status in {"done", "metadata_done"}
            and not self.options.retry_failed
        ):
            self.stats.skipped_items += 1
            return
        if (
            item_state
            and item_state.status in {"metadata_failed", "failed"}
            and not self.options.retry_failed
        ):
            self.stats.skipped_items += 1
            return

        self._progress("info", "metadata", f"Fetching IA metadata: {identifier}")
        try:
            metadata = self.client.get_metadata(identifier)
            item = parse_item_metadata(identifier, metadata)
            self.state.mark_item_metadata(identifier, metadata)
            self._debug(
                "metadata_item",
                f"Captured IA metadata for item {identifier}",
                mediatype=item.mediatype,
                title=item.title,
                collections=",".join(item.collections),
                file_count=len(item.files),
            )
        except Exception as exc:
            self.stats.failed_items += 1
            self.state.mark_item_status(
                identifier,
                "metadata_failed",
                error=str(exc),
                increment_attempts=True,
            )
            self.state.log_event(
                "error",
                f"Metadata fetch failed: {exc}",
                item_identifier=identifier,
            )
            self._progress(
                "error",
                "metadata_failed",
                f"Metadata fetch failed for {identifier}: {exc}",
            )
            return

        download_identity_required = 0
        api_identity_available = 0
        queued_files = 0
        tagged_ia_artifacts = 0
        item_ufid_created = 0
        item_ufid_enriched = 0
        item_ufid_failed = 0
        for ia_file in item.files:
            if is_ia_artifact_file(ia_file):
                tagged_ia_artifacts += 1
            missing_identity = missing_required_ia_identity(ia_file)
            if missing_identity:
                download_identity_required += 1
            else:
                api_identity_available += 1
            queued_files += 1
            self.state.upsert_file(
                item_identifier=identifier,
                ia_file=ia_file,
                url=file_url(identifier, ia_file.name),
                needs_downloaded_identity=bool(missing_identity),
                identity_metadata_status="incomplete" if missing_identity else "complete",
                identity_metadata_missing=missing_identity,
            )
            if missing_identity:
                self._debug_identity_decision(
                    identifier=identifier,
                    ia_file=ia_file,
                    enough_data=False,
                    added_to_database=False,
                    missing_identity=missing_identity,
                    status="needs-download",
                    url=file_url(identifier, ia_file.name),
                )
                continue
            try:
                file_id, created, enriched = self.target.upsert_declared_file(
                    identifier=identifier,
                    ia_file=ia_file,
                    item_metadata=item.raw,
                    hashes=declared_identity_hashes(ia_file),
                    size_bytes=int(ia_file.size),
                )
                self.state.record_file_ufid_identity(
                    identifier,
                    ia_file.name,
                    file_id,
                )
                self.stats.ufid_created += int(created)
                self.stats.ufid_enriched += int(enriched)
                item_ufid_created += int(created)
                item_ufid_enriched += int(enriched)
                self._debug_identity_decision(
                    identifier=identifier,
                    ia_file=ia_file,
                    enough_data=True,
                    added_to_database=True,
                    ufid_file_id=file_id,
                    created=created,
                    enriched=enriched,
                    missing_identity=(),
                    status="created" if created else "enriched" if enriched else "already-present",
                    url=file_url(identifier, ia_file.name),
                )
            except (api_client.UFIDAPIError, IdentityConflict, ValueError) as exc:
                item_ufid_failed += 1
                self.stats.failed_files += 1
                self.state.mark_file_status(
                    identifier,
                    ia_file.name,
                    "failed",
                    error=f"UFID metadata insert failed: {exc}",
                    increment_attempts=True,
                )
                self.state.log_event(
                    "error",
                    f"UFID metadata insert failed: {exc}",
                    item_identifier=identifier,
                    file_name=ia_file.name,
                )
                self._progress(
                    "error",
                    "metadata_ufid_failed",
                    f"UFID metadata insert failed for {identifier}/{ia_file.name}: {exc}",
                )
                self._debug_identity_decision(
                    identifier=identifier,
                    ia_file=ia_file,
                    enough_data=True,
                    added_to_database=False,
                    missing_identity=(),
                    status="database-error",
                    error=str(exc),
                    url=file_url(identifier, ia_file.name),
                )
        self.stats.processed_items += 1
        self._progress(
            "info",
            "metadata_done",
            f"Queued {queued_files} IA file(s) from metadata: {identifier}",
            api_identity_available=api_identity_available,
            download_identity_required=download_identity_required,
            ia_artifacts=tagged_ia_artifacts,
            ufid_created=item_ufid_created,
            ufid_enriched=item_ufid_enriched,
            ufid_failed=item_ufid_failed,
        )

    def _process_file(
        self,
        identifier: str,
        ia_file: IAFile,
        queued_file: QueuedFile,
    ) -> None:
        if self.options.dry_run:
            self._progress(
                "info",
                "dry_run_file",
                f"Would ingest IA file {identifier}/{ia_file.name}",
                needs_downloaded_identity=queued_file.needs_downloaded_identity,
            )
            return

        destination = safe_download_path(
            self.options.cache_dir,
            identifier,
            ia_file.name,
        )
        self.state.mark_file_status(identifier, ia_file.name, "downloading")
        self._progress(
            "info",
            "download",
            f"Downloading IA file {identifier}/{ia_file.name}",
            size_bytes=ia_file.size,
            needs_downloaded_identity=queued_file.needs_downloaded_identity,
            identity_metadata_missing=",".join(queued_file.identity_metadata_missing),
        )
        progress_bar = self._download_progress_bar(ia_file)
        try:
            download = self.client.download_file(
                identifier=identifier,
                ia_file=ia_file,
                destination=destination,
                resume=True,
                progress_callback=None if progress_bar is None else progress_bar.update,
            )
        finally:
            if progress_bar is not None:
                progress_bar.finish()

        hash_result = compute_file_hashes(download.path, algorithms=self.options.algorithms)
        if not self.options.allow_checksum_mismatch:
            verify_declared_fixity(
                identifier=identifier,
                ia_file=ia_file,
                hashes=hash_result.hashes,
            )

        if queued_file.needs_downloaded_identity or queued_file.ufid_file_id is None:
            file_id, created, enriched = self.target.upsert_downloaded_file(
                identifier=identifier,
                ia_file=ia_file,
                item_metadata=self.state.get_item_metadata(identifier),
                local_path=download.path,
                hashes=hash_result.hashes,
                size_bytes=hash_result.size_bytes,
            )
        else:
            file_id = queued_file.ufid_file_id
            created = False
            enriched = False
        self.stats.processed_files += 1
        self.stats.ufid_created += int(created)
        self.stats.ufid_enriched += int(enriched)

        archive_scan = ArchiveScanResult()
        if not self.options.no_archive_scan:
            archive_scan = self.target.scan_archive(
                archive_path=download.path,
                parent_file_id=file_id,
                algorithms=self.options.algorithms,
            )
            if archive_scan.member_count == 0 and _looks_like_unsupported_container(ia_file):
                self.target.add_metadata(
                    file_id,
                    [
                        {
                            "metadata_type": "text",
                            "name": "archive_error",
                            "value": (
                                f"{ia_file.name}: unsupported archive/container "
                                "type pending extractor support"
                            ),
                            "notes": "IA ingest could not inspect this container yet",
                        }
                    ],
                )
                archive_scan.error_count += 1

        self.stats.archive_members += archive_scan.member_count
        self.stats.archive_errors += archive_scan.error_count
        self.state.mark_file_status(
            identifier,
            ia_file.name,
            "done",
            ufid_file_id=file_id,
            downloaded_path=str(download.path),
            size_bytes=hash_result.size_bytes,
            error=None,
        )
        self._progress(
            "info",
            "ufid_file",
            f"UFID {file_id} ingested for {identifier}/{ia_file.name}",
            created=created,
            enriched=enriched,
            archive_members=archive_scan.member_count,
            archive_errors=archive_scan.error_count,
            needs_downloaded_identity=queued_file.needs_downloaded_identity,
        )
        if not self.options.keep_cache:
            try:
                download.path.unlink()
            except OSError as exc:
                self.state.log_event(
                    "warning",
                    f"Could not remove cached file: {exc}",
                    item_identifier=identifier,
                    file_name=ia_file.name,
                )

    def _should_skip_file(self, identifier: str, ia_file: IAFile) -> bool:
        current = self.state.get_file(identifier, ia_file.name)
        if current and current.status == "done" and not self.options.retry_failed:
            self.stats.skipped_files += 1
            return True
        if current and current.status == "failed" and not self.options.retry_failed:
            self.stats.skipped_files += 1
            return True
        reason = None
        if self.options.original_only and ia_file.source != "original":
            reason = "not original"
        if reason is None and (
            self.options.max_file_bytes is not None
            and ia_file.size is not None
            and ia_file.size > self.options.max_file_bytes
        ):
            reason = f"size {ia_file.size} exceeds max {self.options.max_file_bytes}"

        if reason:
            self.stats.skipped_files += 1
            self.state.mark_file_status(
                identifier,
                ia_file.name,
                "skipped",
                error=reason,
            )
            self._progress(
                "info",
                "file_skipped",
                f"Skipped IA file {identifier}/{ia_file.name}: {reason}",
            )
            return True
        return False

    def _should_defer_download(
        self,
        queued_file: QueuedFile,
        ia_file: IAFile,
    ) -> bool:
        if (
            self.options.min_size_bytes is not None
            and (
                ia_file.size is None
                or ia_file.size < self.options.min_size_bytes
            )
        ):
            self.stats.skipped_files += 1
            size_text = "unknown" if ia_file.size is None else str(ia_file.size)
            self._progress(
                "info",
                "download_deferred",
                (
                    f"Deferred IA file {queued_file.item_identifier}/{queued_file.name}: "
                    f"size {size_text} is below --min-size {self.options.min_size_bytes}"
                ),
                size_bytes=ia_file.size,
                min_size_bytes=self.options.min_size_bytes,
            )
            return True

        if (
            self.options.max_size_bytes is not None
            and ia_file.size is not None
            and ia_file.size > self.options.max_size_bytes
        ):
            self.stats.skipped_files += 1
            self._progress(
                "info",
                "download_deferred",
                (
                    f"Deferred IA file {queued_file.item_identifier}/{queued_file.name}: "
                    f"size {ia_file.size} exceeds --max-size {self.options.max_size_bytes}"
                ),
                size_bytes=ia_file.size,
                max_size_bytes=self.options.max_size_bytes,
            )
            return True

        if (
            not self.options.deep_discover_archives
            and not looks_like_supported_archive_container_path(ia_file.name)
        ):
            self.stats.skipped_files += 1
            self._progress(
                "info",
                "download_deferred",
                (
                    f"Deferred IA file {queued_file.item_identifier}/{queued_file.name}: "
                    "not a clearly supported archive"
                ),
                file_format=ia_file.format,
            )
            return True
        return False

    def _requires_download_analysis(
        self,
        queued_file: QueuedFile,
        ia_file: IAFile,
    ) -> bool:
        if queued_file.needs_downloaded_identity or queued_file.ufid_file_id is None:
            return True
        if self.options.no_archive_scan:
            return False
        return _requires_archive_scan(ia_file)

    def _remaining_items(self) -> int | None:
        if self.options.max_items is None:
            return None
        attempted = self.stats.processed_items + self.stats.failed_items
        return max(0, self.options.max_items - attempted)

    def _remaining_files(self) -> int | None:
        if self.options.max_files is None:
            return None
        attempted = self.stats.processed_files + self.stats.failed_files
        return max(0, self.options.max_files - attempted)

    def _progress(self, level: str, event: str, message: str, **details: Any) -> None:
        self.state.log_event(level, message, details={"event": event, **details})
        if self.options.quiet:
            return
        if self.options.jsonl:
            print(
                json.dumps(
                    {
                        "level": level,
                        "event": event,
                        "message": message,
                        **details,
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
            return
        detail_suffix = ""
        if details:
            compact = " ".join(f"{key}={value}" for key, value in details.items())
            detail_suffix = f" ({compact})"
        line = f"[{level}] {message}{detail_suffix}"
        print(self._colorize_line(level, event, line), flush=True)

    def _download_progress_bar(self, ia_file: IAFile) -> "_DownloadProgressBar | None":
        if self.options.quiet or self.options.jsonl:
            return None
        if not bool(getattr(sys.stdout, "isatty", lambda: False)()):
            return None
        return _DownloadProgressBar(
            label=PurePosixPath(ia_file.name).name,
            total_bytes=ia_file.size,
            stream=sys.stdout,
        )

    def _debug(self, event: str, message: str, **details: Any) -> None:
        if not self.options.debug:
            return
        self._progress("debug", event, message, **details)

    def _debug_identity_decision(
        self,
        *,
        identifier: str,
        ia_file: IAFile,
        enough_data: bool,
        added_to_database: bool,
        missing_identity: tuple[str, ...],
        status: str,
        url: str,
        ufid_file_id: int | None = None,
        created: bool = False,
        enriched: bool = False,
        error: str | None = None,
    ) -> None:
        details: dict[str, Any] = {
            "path": ia_file.name,
            "size_bytes": ia_file.size,
            "crc32": ia_file.crc32 or "<missing>",
            "md5": ia_file.md5 or "<missing>",
            "sha1": ia_file.sha1 or "<missing>",
            "enough_data": "yes" if enough_data else "no",
            "added_to_database": "yes" if added_to_database else "no",
            "ufid_target": self._target_label(),
            "ufid_file_id": ufid_file_id or "",
            "created": created,
            "enriched": enriched,
            "missing": ",".join(missing_identity) or "",
            "status": status,
            "url": url,
        }
        if error:
            details["error"] = error
        self._debug(
            "metadata_identity",
            f"IA API identity decision for {identifier}/{ia_file.name}",
            **details,
        )

    def _target_label(self) -> str:
        if self.options.backend:
            return f"backend:{self.options.backend}"
        return f"sqlite:{Path(self.options.db_path).resolve()}"

    def _colorize_line(self, level: str, event: str, line: str) -> str:
        if not _color_enabled():
            return line
        if level == "error":
            return _ansi("red", line)
        if event == "metadata_identity":
            if "added_to_database=yes" in line:
                return _ansi("green", line)
            if "enough_data=no" in line:
                return _ansi("yellow", line)
            return _ansi("red", line)
        if level == "debug":
            return _ansi("cyan", line)
        if level == "info":
            return _ansi("blue", line)
        return line


def ia_metadata(
    identifier: str,
    ia_file: IAFile,
    *,
    item_metadata: Mapping[str, Any] | None = None,
) -> list[dict[str, str]]:
    metadata = [
        {"metadata_type": "text", "name": "source", "value": IA_SOURCE_VALUE},
        {"metadata_type": "text", "name": "ia_identifier", "value": identifier},
        {"metadata_type": "text", "name": "ia_file_name", "value": ia_file.name},
        {
            "metadata_type": "url",
            "name": "ia_item_url",
            "value": f"https://archive.org/details/{identifier}",
        },
        {
            "metadata_type": "url",
            "name": "ia_file_url",
            "value": file_url(identifier, ia_file.name),
        },
    ]
    if is_ia_artifact_file(ia_file):
        metadata.append(
            {
                "metadata_type": "text",
                "name": "tag",
                "value": IA_ARTIFACT_TAG,
            }
        )
    optional_values = {
        "ia_file_source": ia_file.source,
        "ia_file_format": ia_file.format,
        "ia_declared_size": None if ia_file.size is None else str(ia_file.size),
        "ia_declared_mtime": None if ia_file.mtime is None else str(ia_file.mtime),
        "ia_declared_md5": ia_file.md5,
        "ia_declared_sha1": ia_file.sha1,
        "ia_declared_crc32": ia_file.crc32,
    }
    for name, value in optional_values.items():
        if value:
            metadata.append({"metadata_type": "text", "name": name, "value": value})
    metadata.extend(_unpromoted_ia_metadata(item_metadata, ia_file))
    return metadata


def _unpromoted_ia_metadata(
    item_metadata: Mapping[str, Any] | None,
    ia_file: IAFile,
) -> list[dict[str, str]]:
    metadata: list[dict[str, str]] = []
    if item_metadata:
        for key, value in sorted(item_metadata.items()):
            if key in IA_ITEM_CONTAINER_FIELDS:
                continue
            metadata.extend(
                _namespaced_ia_metadata_rows(
                    str(key),
                    value,
                    notes="Internet Archive item record field",
                )
            )

        item_fields = item_metadata.get("metadata")
        if isinstance(item_fields, Mapping):
            for key, value in sorted(item_fields.items()):
                metadata.extend(
                    _namespaced_ia_metadata_rows(
                        str(key),
                        value,
                        notes="Internet Archive item metadata field",
                    )
                )

    for key, value in sorted(ia_file.raw.items()):
        if key in PROMOTED_IA_FILE_FIELDS:
            continue
        metadata.extend(
            _namespaced_ia_metadata_rows(
                str(key),
                value,
                notes="Internet Archive file metadata field",
            )
        )
    return metadata


def _namespaced_ia_metadata_rows(
    name: str,
    value: Any,
    *,
    notes: str,
) -> list[dict[str, str]]:
    normalized_name = f"{IA_METADATA_PREFIX}{name}"
    if isinstance(value, list):
        if not value:
            return [
                _namespaced_ia_metadata_row(
                    normalized_name,
                    value,
                    notes=notes,
                )
            ]
        if all(not isinstance(item, (Mapping, list)) for item in value):
            return [
                _namespaced_ia_metadata_row(
                    normalized_name,
                    item,
                    notes=notes,
                )
                for item in value
            ]
    return [
        _namespaced_ia_metadata_row(
            normalized_name,
            value,
            notes=notes,
        )
    ]


def _namespaced_ia_metadata_row(
    name: str,
    value: Any,
    *,
    notes: str,
) -> dict[str, str]:
    metadata_type, serialized_value = _serialize_ia_metadata_value(value)
    return {
        "metadata_type": metadata_type,
        "name": name,
        "value": serialized_value,
        "notes": notes,
    }


def _serialize_ia_metadata_value(value: Any) -> tuple[str, str]:
    if isinstance(value, (Mapping, list, bool)) or value is None:
        return "json", json.dumps(value, sort_keys=True, separators=(",", ":"))
    if isinstance(value, (int, float)):
        return "number", str(value)
    return "text", str(value)


def queued_file_to_ia_file(queued_file: QueuedFile) -> IAFile:
    raw = queued_file.raw or {
        "name": queued_file.name,
        "source": queued_file.source,
        "format": queued_file.format,
        "size": queued_file.size_bytes,
        "md5": queued_file.md5,
        "sha1": queued_file.sha1,
        "crc32": queued_file.crc32,
        "url": queued_file.url,
    }
    return IAFile(
        name=queued_file.name,
        source=queued_file.source,
        format=queued_file.format,
        size=queued_file.size_bytes,
        md5=queued_file.md5,
        sha1=queued_file.sha1,
        crc32=queued_file.crc32,
        raw=dict(raw),
    )


def declared_identity_hashes(ia_file: IAFile) -> dict[str, str]:
    missing = missing_required_ia_identity(ia_file)
    if missing:
        raise ValueError(
            "IA file is missing required identity fields: " + ", ".join(missing)
        )
    assert ia_file.crc32 is not None
    assert ia_file.md5 is not None
    assert ia_file.sha1 is not None
    return {
        "crc32": ia_file.crc32,
        "md5": ia_file.md5,
        "sha1": ia_file.sha1,
    }


def missing_required_ia_identity(ia_file: IAFile) -> tuple[str, ...]:
    missing: list[str] = []
    if ia_file.size is None or ia_file.size < 0:
        missing.append("size")
    if not _is_hex(ia_file.crc32, 8):
        missing.append("crc32")
    if not _is_hex(ia_file.md5, 32):
        missing.append("md5")
    if not _is_hex(ia_file.sha1, 40):
        missing.append("sha1")
    return tuple(missing)


def _is_hex(value: str | None, length: int) -> bool:
    if value is None:
        return False
    text = str(value).strip().lower()
    if len(text) != length:
        return False
    return all(character in "0123456789abcdef" for character in text)


def parse_size_limit(value: str) -> int:
    text = str(value or "").strip()
    match = re.fullmatch(r"(?i)(\d+(?:\.\d+)?)\s*([kmgtp]?i?b?|bytes?)?", text)
    if match is None:
        raise argparse.ArgumentTypeError(
            "size must be a number optionally followed by K, M, G, T, or P"
        )

    number = float(match.group(1))
    if number < 0:
        raise argparse.ArgumentTypeError("size cannot be negative")
    suffix = (match.group(2) or "b").lower()
    suffix = suffix.removesuffix("bytes").removesuffix("byte")
    suffix = suffix.removesuffix("ib").removesuffix("b")
    suffix = suffix.removesuffix("i")
    multipliers = {
        "": 1,
        "k": 1024,
        "m": 1024**2,
        "g": 1024**3,
        "t": 1024**4,
        "p": 1024**5,
    }
    multiplier = multipliers.get(suffix)
    if multiplier is None:
        raise argparse.ArgumentTypeError(
            "size suffix must be one of K, M, G, T, or P"
        )
    return int(number * multiplier)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ufid-ia-ingest",
        description="Ingest Internet Archive item files into UFID.",
    )
    parser.add_argument(
        "--mode",
        choices=INGEST_MODES,
        default="all",
        help=(
            "all = metadata queue then download queue; metadata = discover items, "
            "fetch IA metadata/hashes, queue files, and immediately insert complete "
            "API-declared identities into UFID; download = process queued files "
            "that need byte-level identity or archive analysis."
        ),
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--collection",
        default=DEFAULT_COLLECTION,
        help=f"Internet Archive collection identifier. Defaults to {DEFAULT_COLLECTION}.",
    )
    source.add_argument("--query", help="Explicit Internet Archive search query.")

    target = parser.add_mutually_exclusive_group()
    target.add_argument("--backend", help="UFID backend base URL.")
    target.add_argument(
        "--db",
        default=str(default_sqlite_db_path()),
        help="SQLite UFID database path for local ingestion.",
    )

    parser.add_argument(
        "--api-token",
        help=(
            "Bearer token for UFID backend API calls. Defaults to UFID_API_TOKEN "
            "or the saved session for --backend."
        ),
    )
    parser.add_argument("--state-db", default=str(default_ia_state_db_path()))
    parser.add_argument("--cache", default=str(default_ia_cache_dir()))
    parser.add_argument("--crawl-name", help="Stable checkpoint key. Defaults to query.")
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT)
    parser.add_argument("--scrape-count", type=int, default=1000)
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("--max-retries", type=int, default=5)
    parser.add_argument("--request-delay", type=float, default=0.25)
    parser.add_argument("--download-delay", type=float, default=0.5)
    parser.add_argument("--max-items", type=int)
    parser.add_argument("--max-files", type=int)
    parser.add_argument("--max-file-bytes", type=int)
    parser.add_argument(
        "--min-size",
        type=parse_size_limit,
        dest="min_size_bytes",
        help=(
            "Defer queued downloads smaller than this size without changing their "
            "queue status. Accepts byte values plus K, M, G, T, or P suffixes, "
            "for example 100k, 2M, or 60G."
        ),
    )
    parser.add_argument(
        "--max-size",
        type=parse_size_limit,
        dest="max_size_bytes",
        help=(
            "Defer queued downloads larger than this size without changing their "
            "queue status. Accepts byte values plus K, M, G, T, or P suffixes, "
            "for example 100k, 2M, or 60G."
        ),
    )
    parser.add_argument("--original-only", action="store_true")
    parser.add_argument("--keep-cache", action="store_true")
    parser.add_argument("--retry-failed", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--no-archive-scan", action="store_true")
    parser.add_argument(
        "--deep-discover-archives",
        action="store_true",
        help=(
            "Allow the download worker to process non-archive or unsupported "
            "container-looking queue rows. By default, download mode only "
            "downloads clearly supported archive files."
        ),
    )
    parser.add_argument("--allow-checksum-mismatch", action="store_true")
    parser.add_argument(
        "--discover-collections",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "When IA search results include mediatype=collection records, also "
            "scrape those collection identifiers for child items. Enabled by "
            "default; pass --no-discover-collections to disable."
        ),
    )
    parser.add_argument(
        "--collection-depth",
        type=int,
        default=1,
        help="Maximum nested IA collection depth to discover when enabled.",
    )
    parser.add_argument(
        "--max-collections",
        type=int,
        help="Maximum number of discovered IA collection queries to scan.",
    )
    parser.add_argument(
        "--algorithm",
        action="append",
        choices=SUPPORTED_ALGORITHMS,
        help="Hash algorithm to compute. Can be repeated.",
    )
    parser.add_argument("--jsonl", action="store_true", help="Emit progress as JSON Lines.")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument(
        "--debug",
        action="store_true",
        help=(
            "Emit step-by-step IA metadata and queue details, including "
            "declared file hashes captured from the Internet Archive API."
        ),
    )
    return parser


def options_from_args(args: argparse.Namespace) -> IngestOptions:
    query = args.query or f"collection:{args.collection}"
    max_collections = (
        None if args.max_collections is None else max(0, int(args.max_collections))
    )
    if (
        args.min_size_bytes is not None
        and args.max_size_bytes is not None
        and args.min_size_bytes > args.max_size_bytes
    ):
        raise ValueError("--min-size cannot be larger than --max-size")
    return IngestOptions(
        mode=args.mode,
        query=query,
        crawl_key=args.crawl_name or query,
        backend=args.backend,
        api_token=args.api_token,
        db_path=args.db,
        state_db=args.state_db,
        cache_dir=Path(args.cache),
        user_agent=args.user_agent,
        algorithms=tuple(args.algorithm or DEFAULT_ALGORITHMS),
        scrape_count=args.scrape_count,
        timeout=args.timeout,
        max_retries=args.max_retries,
        request_delay_seconds=args.request_delay,
        download_delay_seconds=args.download_delay,
        max_items=args.max_items,
        max_files=args.max_files,
        max_file_bytes=args.max_file_bytes,
        min_size_bytes=args.min_size_bytes,
        max_size_bytes=args.max_size_bytes,
        original_only=bool(args.original_only),
        keep_cache=bool(args.keep_cache),
        retry_failed=bool(args.retry_failed),
        dry_run=bool(args.dry_run),
        no_archive_scan=bool(args.no_archive_scan),
        deep_discover_archives=bool(args.deep_discover_archives),
        allow_checksum_mismatch=bool(args.allow_checksum_mismatch),
        discover_collections=bool(args.discover_collections),
        max_collection_depth=max(0, int(args.collection_depth)),
        max_collections=max_collections,
        jsonl=bool(args.jsonl),
        quiet=bool(args.quiet),
        debug=bool(args.debug),
    )


def collection_query(identifier: str) -> str:
    return f"collection:{identifier.strip()}"


def collection_identifier_from_query(query: str) -> str | None:
    text = query.strip()
    prefix = "collection:"
    if not text.lower().startswith(prefix):
        return None
    identifier = text[len(prefix) :].strip().strip('"')
    if not identifier or any(character.isspace() for character in identifier):
        return None
    return identifier


def collection_crawl_key(root_crawl_key: str, identifier: str) -> str:
    del root_crawl_key
    return f"collection::{identifier.strip()}"


def _coerce_non_negative_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _looks_like_unsupported_container(ia_file: IAFile) -> bool:
    name = ia_file.name.lower()
    if looks_like_archive_path(name):
        return False
    if name.endswith(UNSUPPORTED_CONTAINER_SUFFIXES):
        return True
    file_format = (ia_file.format or "").lower()
    return any(
        token in file_format
        for token in ("iso", "7z", "rar", "disk image", "cd-rom", "cd image")
    )


def _requires_archive_scan(ia_file: IAFile) -> bool:
    name = ia_file.name
    return (
        looks_like_archive_path(name)
        and not looks_like_single_file_compression_path(name)
    ) or _looks_like_unsupported_container(ia_file)


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


class _DownloadProgressBar:
    def __init__(
        self,
        *,
        label: str,
        total_bytes: int | None,
        stream,
    ) -> None:
        self.label = _shorten_progress_label(label)
        self.total_bytes = total_bytes
        self.stream = stream
        self._last_width = 0
        self._started = False

    def update(self, bytes_written: int, total_bytes: int | None) -> None:
        total = total_bytes if total_bytes is not None else self.total_bytes
        line = _format_download_progress(
            label=self.label,
            bytes_written=max(0, int(bytes_written)),
            total_bytes=total,
        )
        padding = " " * max(0, self._last_width - len(line))
        self.stream.write(f"\r{line}{padding}")
        self.stream.flush()
        self._last_width = len(line)
        self._started = True

    def finish(self) -> None:
        if self._started:
            self.stream.write("\n")
            self.stream.flush()


def _format_download_progress(
    *,
    label: str,
    bytes_written: int,
    total_bytes: int | None,
    width: int = 28,
) -> str:
    if total_bytes is not None and total_bytes > 0:
        ratio = min(max(bytes_written / total_bytes, 0.0), 1.0)
        filled = min(width, int(round(width * ratio)))
        bar = "#" * filled + "-" * (width - filled)
        return (
            f"  {label} [{bar}] {ratio * 100:5.1f}% "
            f"{_format_byte_count(bytes_written)}/{_format_byte_count(total_bytes)}"
        )

    return f"  {label} {_format_byte_count(bytes_written)} downloaded"


def _shorten_progress_label(label: str, max_length: int = 36) -> str:
    text = label or "download"
    if len(text) <= max_length:
        return text
    return "..." + text[-(max_length - 3):]


def _format_byte_count(value: int) -> str:
    amount = float(max(0, value))
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or unit == "TiB":
            if unit == "B":
                return f"{int(amount)} {unit}"
            return f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{amount:.1f} TiB"


ANSI_COLORS = {
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "cyan": "\033[36m",
    "reset": "\033[0m",
}


def _color_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("UFID_COLOR", "").lower() in {"1", "true", "yes", "always"}:
        return True
    return bool(getattr(sys.stdout, "isatty", lambda: False)())


def _ansi(color: str, text: str) -> str:
    return f"{ANSI_COLORS[color]}{text}{ANSI_COLORS['reset']}"


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        options = options_from_args(args)
        runner = IAIngestRunner(options)
    except ValueError as exc:
        parser.exit(2, f"ufid-ia-ingest: {exc}\n")
    try:
        runner.run()
    except (IAClientError, api_client.UFIDAPIError, IdentityConflict, ValueError) as exc:
        parser.exit(2, f"ufid-ia-ingest: {exc}\n")
    finally:
        runner.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
