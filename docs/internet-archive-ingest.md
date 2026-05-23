# Internet Archive UFID Ingest

`ufid-ia-ingest` has two independent queues:

- the Internet Archive metadata queue, which discovers items, fetches IA
  metadata/API hashes, queues every listed IA file, and immediately
  inserts/enriches UFID records when IA provides the complete required identity;
- the download/analyze queue, which downloads queued files only when byte-level
  identity is still missing or archive/container analysis is needed, then scans
  supported archives.

The two queues can be run together or separately.

The default collection is `software`, Internet Archive's broad software/computer
collection.

## Safe First Run

Start with a small bounded run:

```powershell
ufid ia-ingest `
  --backend http://127.0.0.1:8765 `
  --collection software `
  --max-items 1
```

That uses the default `--mode all`, which runs metadata discovery first and then
processes queued downloads.

On Windows, for local SQLite-only discovery mode plus the local web/API server:

```powershell
.\scripts\start_windows_local_ia_discovery.ps1 -MaxItems 1000
```

Installed environments can run the same helper directly:

```powershell
ufid-local-ia-discovery --max-items 1000
```

The Windows launcher checks that `/health` is answered by UFID itself. If the
requested port is occupied by another local program, it scans forward and prints
the actual URL it selected. Use `-Port` and `-PortScanCount` to pin or limit
that behavior.

For local SQLite instead of the UFID API:

```powershell
ufid ia-ingest `
  --collection software `
  --max-items 1
```

## Production Shape

Use the UFID API backend after logging in:

```powershell
ufid auth login --backend https://ufid.example.com --username admin
ufid ia-ingest --backend https://ufid.example.com --collection software
```

The CLI reuses the saved UFID bearer session for the matching backend URL.

## Independent Queue Modes

Metadata/API harvesting only:

```powershell
ufid ia-ingest `
  --mode metadata `
  --backend https://ufid.example.com `
  --collection software `
  --max-items 1000
```

This mode:

- uses the IA Scrape API to discover item identifiers;
- fetches `/metadata/{identifier}?extended_err=1`;
- stores item metadata JSON in the state DB;
- stores each IA file row with declared size, `crc32`, `md5`, `sha1`, source,
  format, stable download URL, and the raw IA file metadata JSON needed for
  later UFID enrichment;
- inserts/enriches UFID records immediately for rows with complete declared
  `size`, `crc32`, `md5`, and `sha1`;
- adds all IA item/file metadata not already mapped to UFID's compact IA
  provenance fields as UFID metadata rows named `org.archive-*`;
- marks each file row with `needs_downloaded_identity` when the IA metadata is
  missing any part of UFID's required identity tuple: size, `crc32`, `md5`, or
  `sha1`;
- does not download IA files.

Download/analyze only:

```powershell
ufid ia-ingest `
  --mode download `
  --backend https://ufid.example.com `
  --max-files 100
```

This mode:

- reads queued file rows from the state DB;
- does not call IA Scrape API;
- does not refetch IA item metadata;
- by default, downloads file bytes only for queue rows that are clearly
  supported archive files;
- computes UFID hashes locally;
- checks IA-declared fixity by default;
- inserts/enriches UFID when a queue row is marked `needs_downloaded_identity`
  because the IA metadata record was not sufficient on its own;
- skips downloads for complete, already-stored IA API identities that do not
  look like archives or containers.

Queue rows that need byte-level identity but are not clearly supported archive
files are left pending. Process those broader rows explicitly with:

```powershell
ufid ia-ingest `
  --mode download `
  --backend https://ufid.example.com `
  --deep-discover-archives
```

To leave small or large queue rows untouched during a controlled pass, use
`--min-size` and/or `--max-size`. The suffixes use powers of 1024:

```powershell
ufid ia-ingest `
  --mode download `
  --backend https://ufid.example.com `
  --min-size 1M `
  --max-size 2G
```

Rows smaller than `--min-size`, rows with unknown IA metadata size when
`--min-size` is set, and rows larger than `--max-size` are not marked `skipped`
or `failed`; a later run without those limits will still find them pending.

Combined mode:

```powershell
ufid ia-ingest --mode all --backend https://ufid.example.com
```

`all` is convenient for small or supervised runs. For real Internet Archive
ingestion, prefer scheduled `metadata` jobs and separate controlled `download`
workers.

Use a descriptive Internet Archive User-Agent:

```powershell
ufid ia-ingest `
  --backend https://ufid.example.com `
  --collection software `
  --user-agent "UFID-IA-Ingest/0.9 (gpt-5; contact: you@example.com)"
```

Do not use browser-spoofed or stealth User-Agent strings. A clear tool name and
contact is better operationally and makes access-control or rate-limit problems
diagnosable.

## Resume And Retry

The state database stores:

- scrape cursor checkpoints
- discovered item identifiers
- per-item metadata status
- per-file metadata/API hashes
- per-file download/UFID status
- whether IA metadata was sufficient for UFID identity, plus the missing fields
- UFID file IDs
- errors and progress events

Restarting the same command continues from state. Failed items/files are skipped
unless you pass:

```powershell
--retry-failed
```

## Rate Limits

Defaults are intentionally conservative:

```text
request delay:  0.25 seconds
download delay: 0.5 seconds
max retries:    5
```

The client retries `429`, `500`, `502`, `503`, and `504`, honors
`Retry-After`, and uses exponential backoff for transient failures.

Tuning flags:

```powershell
--request-delay 1.0
--download-delay 1.0
--max-retries 8
--timeout 120
```

## File Selection

Download mode only downloads rows that need byte-level identity or archive
analysis. Rows whose IA metadata already provided a complete UFID identity are
marked done without download unless they are archive containers that need
member expansion. Plain single-file compression derivatives such as
`*_hocr.html.gz` are not archive-scan candidates by default. Crawl index/data
files ending in `.cdx.gz` or `.warc.gz` are always treated as non-archive files.
Internet Archive-generated artifact files such as `*_files.xml`,
`*_meta.sqlite`, `*_meta.xml`, and `*_archive.torrent` are ingested when they
have enough identity data. UFID tags recognized artifact records with
`IA Artefacts` metadata so they remain distinguishable from original item files.

Useful limiting flags:

```powershell
--original-only
--max-file-bytes 1073741824
--min-size 1M
--max-size 2G
--max-items 100
--max-files 1000
```

## Archive Handling

Supported now:

- ZIP
- TAR
- TGZ / TAR.GZ
- TBZ2 / TAR.BZ2
- TXZ / TAR.XZ
- many legacy archive and disk-image formats when `7z`/`7zz`/`7za` or
  `bsdtar` is installed

Supported archives are scanned using UFID's existing archive-member model:

```text
parent_file_id = UFID of the IA archive/container file
child_file_id  = UFID of the extracted file
archive_path   = internal path inside the archive
```

Containers that cannot be opened, including ISO and other CD/disk images when no
external extractor is installed, are still inserted as UFID files. The tool
records an `archive_error` metadata row noting that content extraction failed or
is pending extractor support.

See [archive-extractors.md](archive-extractors.md) for the current extraction
layers and recommended external tools.

## Fixity Policy

UFID identity always comes from locally read bytes.

Internet Archive declared hashes are recorded as metadata and used as a
download-integrity check. By default, a declared checksum mismatch fails that
file and records the failure in the state database.

To ingest anyway:

```powershell
--allow-checksum-mismatch
```

Use that only for forensic/manual reconciliation runs.

## Progress

Human-readable progress is printed by default.
During interactive download runs, each active file download also renders a
single-line progress bar with bytes written and percentage when IA metadata
includes the file size. The progress bar is not emitted for `--jsonl`, `--quiet`,
or non-interactive output redirection.

For step-by-step metadata queue details, including each IA file row's declared
size, `crc32`, `md5`, and `sha1` values captured from the IA API:

```powershell
ufid ia-ingest --mode metadata --collection software --debug
ufid-local-ia-discovery --debug --max-items 100
```

For machine-readable logs:

```powershell
--jsonl
```

For quiet cron/systemd use:

```powershell
--quiet
```

The state database still receives progress/error events even when output is
quiet.
