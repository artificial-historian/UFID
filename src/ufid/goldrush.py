from __future__ import annotations

from dataclasses import dataclass
import re
import xml.etree.ElementTree as ET
from typing import Any


@dataclass(frozen=True)
class DatImportSummary:
    source_name: str
    alerts: list[dict[str, Any]]


def parse_logiqx_dat(text: str, *, filename: str | None = None) -> DatImportSummary:
    source_text = str(text or "").lstrip("\ufeff")
    if not source_text.strip():
        raise ValueError("DAT file is empty")

    if source_text.lstrip().startswith("<"):
        return _parse_xml_dat(source_text, filename=filename)
    return _parse_classic_dat(source_text, filename=filename)


def _parse_xml_dat(text: str, *, filename: str | None) -> DatImportSummary:
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid XML DAT: {exc}") from exc

    header = _first_child(root, "header")
    source_name = (
        _child_text(header, "name")
        or _child_text(header, "description")
        or _clean_text(filename)
        or "Logiqx DAT import"
    )
    alerts: list[dict[str, Any]] = []
    for set_node in root.iter():
        if _local_name(set_node.tag) not in {"game", "machine", "software"}:
            continue
        set_name = (
            _clean_text(set_node.attrib.get("name"))
            or _child_text(set_node, "description")
            or source_name
        )
        for data_node in set_node.iter():
            if data_node is set_node:
                continue
            if _local_name(data_node.tag) not in {"rom", "disk"}:
                continue
            alert = _alert_from_dat_row(
                set_name=set_name,
                source_name=source_name,
                source_type="logiqx-dat-xml",
                row_name=_clean_text(data_node.attrib.get("name")),
                size_bytes=data_node.attrib.get("size"),
                crc=data_node.attrib.get("crc"),
                md5=data_node.attrib.get("md5"),
                sha1=data_node.attrib.get("sha1"),
                sha256=data_node.attrib.get("sha256"),
                blake3=data_node.attrib.get("blake3"),
            )
            if alert is not None:
                alerts.append(alert)

    if not alerts:
        raise ValueError("DAT file does not contain any ROM or disk rows with supported hashes")
    return DatImportSummary(source_name=source_name, alerts=alerts)


def _parse_classic_dat(text: str, *, filename: str | None) -> DatImportSummary:
    tokens = _tokenize_classic_dat(text)
    if not tokens:
        raise ValueError("DAT file is empty")
    parser = _ClassicDatParser(tokens)
    entries = parser.parse_entries()

    header = _first_block(entries, "clrmamepro") or _first_block(entries, "datafile")
    source_name = (
        _entry_text(header, "name")
        or _entry_text(header, "description")
        or _clean_text(filename)
        or "Logiqx DAT import"
    )

    alerts: list[dict[str, Any]] = []
    for set_block in _blocks_named(entries, {"game", "machine", "software"}):
        set_name = _entry_text(set_block, "name") or _entry_text(set_block, "description") or source_name
        for row_name, row_block in _named_blocks_recursive(set_block, {"rom", "disk"}):
            alert = _alert_from_dat_row(
                set_name=set_name,
                source_name=source_name,
                source_type="logiqx-dat-classic",
                row_name=_entry_text(row_block, "name") or row_name,
                size_bytes=_entry_text(row_block, "size"),
                crc=_entry_text(row_block, "crc"),
                md5=_entry_text(row_block, "md5"),
                sha1=_entry_text(row_block, "sha1"),
                sha256=_entry_text(row_block, "sha256"),
                blake3=_entry_text(row_block, "blake3"),
            )
            if alert is not None:
                alerts.append(alert)

    if not alerts:
        raise ValueError("DAT file does not contain any ROM or disk rows with supported hashes")
    return DatImportSummary(source_name=source_name, alerts=alerts)


def _alert_from_dat_row(
    *,
    set_name: str,
    source_name: str,
    source_type: str,
    row_name: str | None,
    size_bytes: Any,
    crc: Any,
    md5: Any,
    sha1: Any,
    sha256: Any,
    blake3: Any,
) -> dict[str, Any] | None:
    hashes = {
        "crc32": crc,
        "md5": md5,
        "sha1": sha1,
        "sha256": sha256,
        "blake3": blake3,
    }
    if not any(_clean_text(value) for value in hashes.values()):
        return None
    return {
        "name": set_name,
        "description": source_name,
        "size_bytes": size_bytes,
        "hashes": hashes,
        "source_type": source_type,
        "source_name": source_name,
        "source_detail": row_name,
    }


def _tokenize_classic_dat(text: str) -> list[str]:
    token_pattern = re.compile(r'"(?:\\.|[^"\\])*"|[()]|[^\s()]+')
    return token_pattern.findall(text)


class _ClassicDatParser:
    def __init__(self, tokens: list[str]) -> None:
        self._tokens = tokens
        self._index = 0

    def parse_entries(self, *, stop_at_paren: bool = False) -> list[tuple[str, Any]]:
        entries: list[tuple[str, Any]] = []
        while self._index < len(self._tokens):
            token = self._tokens[self._index]
            if token == ")":
                if stop_at_paren:
                    return entries
                raise ValueError("Unexpected ')' in classic DAT")
            if token == "(":
                raise ValueError("Unexpected '(' in classic DAT")
            key = token.lower()
            self._index += 1
            if self._index >= len(self._tokens):
                raise ValueError(f"Missing value for classic DAT field '{key}'")
            if self._tokens[self._index] == "(":
                self._index += 1
                value = self.parse_entries(stop_at_paren=True)
                if self._index >= len(self._tokens) or self._tokens[self._index] != ")":
                    raise ValueError(f"Unclosed classic DAT block '{key}'")
                self._index += 1
            else:
                value = _unquote_classic_value(self._tokens[self._index])
                self._index += 1
            entries.append((key, value))
        if stop_at_paren:
            raise ValueError("Unclosed classic DAT block")
        return entries


def _unquote_classic_value(value: str) -> str:
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return re.sub(r'\\(["\\])', r"\1", value[1:-1])
    return value


def _first_block(entries: list[tuple[str, Any]] | None, name: str) -> list[tuple[str, Any]] | None:
    if entries is None:
        return None
    for key, value in entries:
        if key == name and isinstance(value, list):
            return value
    return None


def _blocks_named(
    entries: list[tuple[str, Any]],
    names: set[str],
) -> list[list[tuple[str, Any]]]:
    return [
        value
        for key, value in entries
        if key in names and isinstance(value, list)
    ]


def _named_blocks_recursive(
    entries: list[tuple[str, Any]],
    names: set[str],
) -> list[tuple[str, list[tuple[str, Any]]]]:
    found: list[tuple[str, list[tuple[str, Any]]]] = []
    for key, value in entries:
        if not isinstance(value, list):
            continue
        if key in names:
            found.append((key, value))
        found.extend(_named_blocks_recursive(value, names))
    return found


def _entry_text(entries: list[tuple[str, Any]] | None, name: str) -> str | None:
    if entries is None:
        return None
    for key, value in entries:
        if key == name and not isinstance(value, list):
            return _clean_text(value)
    return None


def _first_child(element: ET.Element | None, name: str) -> ET.Element | None:
    if element is None:
        return None
    for child in element:
        if _local_name(child.tag) == name:
            return child
    return None


def _child_text(element: ET.Element | None, name: str) -> str | None:
    child = _first_child(element, name)
    if child is None:
        return None
    return _clean_text(child.text)


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def _clean_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
