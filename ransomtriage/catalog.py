"""Load the bundled ransomware family / decryptor catalog (signatures.json)."""

from __future__ import annotations

import json
import pkgutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

VALID_STATUSES = frozenset({"AVAILABLE", "PARTIAL_OR_OFFLINE_ONLY", "LEAKED_KEY_SET", "NONE_KNOWN", "WIPER"})


@dataclass(frozen=True)
class Decryptor:
    name: str
    provider: str
    url: str
    notes: str
    id: str = ""
    source_urls: tuple[str, ...] = ()
    last_verified: str = ""


@dataclass(frozen=True)
class Signature:
    family: str
    aliases: tuple[str, ...]
    decryptability_status: str
    exfiltration_risk: str
    note_filenames: tuple[str, ...]
    note_keywords: tuple[str, ...]
    self_names: tuple[str, ...]
    extensions: tuple[str, ...]
    weak_extensions: tuple[str, ...]
    extension_patterns: tuple[str, ...]
    decryptors: tuple[str, ...]
    summary: str
    preserve_advice: str
    sources: tuple[str, ...]
    last_verified: str


@dataclass(frozen=True)
class Catalog:
    signatures: tuple[Signature, ...]
    decryptors: dict[str, Decryptor]
    general_resources: tuple[Decryptor, ...]
    updated: str = ""


def load_catalog(path: Path | None = None) -> Catalog:
    """Load the catalog from *path*, or from the copy bundled with the package (works inside a zipapp)."""
    if path is not None:
        raw_text = path.read_text(encoding="utf-8")
    else:
        data_bytes = pkgutil.get_data("ransomtriage", "signatures.json")
        if data_bytes is None:  # pragma: no cover - defensive
            data_bytes = (Path(__file__).resolve().parent / "signatures.json").read_bytes()
        raw_text = data_bytes.decode("utf-8")
    data = json.loads(raw_text)

    decryptors = {item["id"]: _decryptor_from_json(item) for item in data.get("decryptors", [])}
    general_resources = tuple(_decryptor_from_json(item) for item in data.get("general_resources", []))
    signatures = tuple(_signature_from_json(item) for item in data.get("signatures", []))
    return Catalog(
        signatures=signatures,
        decryptors=decryptors,
        general_resources=general_resources,
        updated=data.get("catalog_updated", ""),
    )


def _decryptor_from_json(item: dict[str, Any]) -> Decryptor:
    return Decryptor(
        id=item.get("id", ""),
        name=item["name"],
        provider=item["provider"],
        url=item["url"],
        notes=item.get("notes", ""),
        source_urls=tuple(item.get("source_urls", [])),
        last_verified=item.get("last_verified", ""),
    )


def _signature_from_json(item: dict[str, Any]) -> Signature:
    return Signature(
        family=item["family"],
        aliases=tuple(item.get("aliases", [])),
        decryptability_status=item.get("decryptability_status", "NONE_KNOWN"),
        exfiltration_risk=item.get("exfiltration_risk", "unknown"),
        note_filenames=tuple(v.lower() for v in item.get("note_filenames", [])),
        note_keywords=tuple(normalize_text(v) for v in item.get("note_keywords", [])),
        self_names=tuple(normalize_text(v) for v in item.get("self_names", [])),
        extensions=tuple(_ext(v) for v in item.get("extensions", [])),
        weak_extensions=tuple(_ext(v) for v in item.get("weak_extensions", [])),
        extension_patterns=tuple(item.get("extension_patterns", [])),
        decryptors=tuple(item.get("decryptors", [])),
        summary=item.get("summary", ""),
        preserve_advice=item.get("preserve_advice", ""),
        sources=tuple(item.get("sources", [])),
        last_verified=item.get("last_verified", ""),
    )


def _ext(value: str) -> str:
    value = value.lower()
    return value if value.startswith(".") else f".{value}"


def normalize_text(value: str) -> str:
    """Lower-case, normalise curly apostrophes and collapse whitespace."""
    return " ".join(value.lower().replace("\u2019", "'").replace("\u2018", "'").split())
