# Archive And Disk Image Extraction

UFID has a layered archive reader:

1. Built-in Python readers for common ZIP/TAR cases.
2. Built-in single-file decompression for gzip, bzip2, xz, and lzma.
3. Optional Python `zstandard` support for `.zst`.
4. External extractor fallbacks when available.

The archive scanner records `archive_error` metadata instead of crashing when a
container is corrupt, encrypted, unsupported, or no extractor is installed.

## Built In

Available with the base UFID install:

- ZIP
- JAR/WAR/EAR/APK/XPI/CRX when they are normal ZIP containers
- TAR
- TGZ / TAR.GZ
- TBZ2 / TAR.BZ2
- TXZ / TAR.XZ
- single-file `.gz`
- single-file `.bz2`
- single-file `.xz`
- single-file `.lzma`

## Optional Python Dependency

For Zstandard single-file payloads:

```bash
python -m pip install -e ".[archives]"
```

This enables `.zst` decompression in the built-in path.

## External Extractors

Install at least one of these for broad legacy archive and disk-image support:

- 7-Zip command line: `7z`, `7zz`, `7za`, or `7zr`
- bsdtar/libarchive: `bsdtar`

UFID auto-detects these tools from `PATH`.
It also checks directories listed in `UFID_ARCHIVE_TOOL_PATH`, separated with
the platform path separator (`;` on Windows, `:` on Linux/macOS).

## Setup And Coverage Report

Use the setup script to report what is active on the current machine:

```powershell
ufid-archive-tools
```

To download portable tools where possible and collect installer/build-only
packages under `manual-install`:

```powershell
ufid-archive-tools --download
```

The tool stores portable extractor state under the configured UFID data root,
which defaults to `D:\UFID-data` in this checkout:

```text
D:\UFID-data\archive-extractors\
  bin/
  downloads/
  manual-install/
```

The script creates activation helpers:

```powershell
. D:\UFID-data\archive-extractors\activate-archive-tools.ps1
```

On Linux/macOS:

```bash
. /path/to/ufid-data/archive-extractors/activate-archive-tools.sh
```

The current automatic portable setup target is official 7-Zip. The script also
downloads libarchive source into `manual-install` as the manual path for
`bsdtar` when no portable binary is available.

Depending on the installed tool build, this can cover formats such as:

- old and unusual ZIP methods, including cases Python cannot read
- ZIPX
- 7z
- RAR
- CAB
- ARJ
- LHA/LZH
- CPIO
- RPM
- DEB
- WIM/SWM/ESD
- CHM
- MSI/NSIS
- ISO/UDF
- DMG
- IMG/NRG/MDF/CDI/CCD style images where the extractor supports them
- VHD/VHDX and other filesystem/disk-image containers where supported

External tool support varies by platform and package. UFID treats these as
best-effort extractors and records a clear `archive_error` if a given file
cannot be listed or extracted.

## Encrypted Archives

UFID does not currently accept passwords. Encrypted members are recorded as
archive errors, and the containing archive is still stored as a UFID file.

## Internet Archive Ingest

`ufid-ia-ingest` uses this same archive layer. That means installing 7-Zip or
bsdtar improves both local `ufid-add` and Internet Archive ingestion.

ISO support is still dependent on an external extractor at this stage. Without
one, the ISO itself is ingested, and UFID records that the contents could not be
opened.
