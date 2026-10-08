"""Extract indicators (wallets, Tor URLs, contacts, victim IDs) from ransom-note text."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .btc import is_valid_bitcoin_address


@dataclass
class ExtractedIOCs:
    bitcoin_addresses: list[str] = field(default_factory=list)
    monero_addresses: list[str] = field(default_factory=list)
    ethereum_addresses: list[str] = field(default_factory=list)
    onion_urls: list[str] = field(default_factory=list)
    tox_ids: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    telegram_handles: list[str] = field(default_factory=list)
    victim_ids: list[str] = field(default_factory=list)
    deadlines: list[str] = field(default_factory=list)
    ransom_amounts: list[str] = field(default_factory=list)
    #: A personal ID ending in "t1" was found. For STOP/Djvu this usually marks an OFFLINE ID;
    #: it does NOT guarantee decryption (Emsisoft must hold that specific offline key).
    stop_djvu_offline_key: bool = False
    notes: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (
            self.bitcoin_addresses
            or self.monero_addresses
            or self.ethereum_addresses
            or self.onion_urls
            or self.tox_ids
            or self.emails
            or self.telegram_handles
            or self.victim_ids
            or self.deadlines
            or self.ransom_amounts
        )


RE_BTC_LEGACY = re.compile(r"(?<![A-Za-z0-9])([13][a-km-zA-HJ-NP-Z1-9]{25,34})(?![A-Za-z0-9])")
RE_BTC_BECH32 = re.compile(r"(?<![A-Za-z0-9])(bc1[ac-hj-np-z02-9]{11,71})(?![A-Za-z0-9])", re.IGNORECASE)
RE_ETH = re.compile(r"\b(0x[a-fA-F0-9]{40})\b")
# Monero addresses are matched by shape only (no Keccak checksum in the standard library).
RE_XMR = re.compile(r"\b([48][0-9AB][1-9A-HJ-NP-Za-km-z]{93})\b")
# v3 onion addresses are 56 base32 characters; legacy v2 addresses were 16.
RE_ONION = re.compile(
    r"(?:https?://)?(?<![a-z0-9])((?:[a-z0-9-]+\.)*(?:[a-z2-7]{56}|[a-z2-7]{16})\.onion(?::\d+)?(?:/[^\s\"'<>]*)?)",
    re.IGNORECASE,
)
RE_TOX = re.compile(r"\b([A-Fa-f0-9]{76})\b")
RE_EMAIL = re.compile(r"\b([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,})\b")
# "@handle" must not be preceded by an email local-part character, and must not be followed by
# ".tld" (which would make it an email domain such as "user@company.com").
RE_TELEGRAM = re.compile(r"(?:(?<![A-Za-z0-9_.+\-])@|\bt\.me/)([A-Za-z][A-Za-z0-9_]{4,31})\b(?!\.[A-Za-z0-9-])")
RE_VICTIM_ID = re.compile(
    r"(?:personal\s+id|your\s+id|victim\s+id|key\s+id|decryption\s+id|client\s+id|company\s+id|unique\s+id)"
    r"\s*[:=\-]?[ \t]*([A-Za-z0-9_\-]{8,64})",
    re.IGNORECASE,
)
RE_ID_HEADER = re.compile(r"(?:personal|victim|decryption|unique)\s+id\s*:?\s*$", re.IGNORECASE)
RE_DEADLINE = re.compile(r"\b(\d+\s*(?:hours?|hrs|days?|minutes?|mins))\b", re.IGNORECASE)
RE_RANSOM_AMOUNT = re.compile(
    r"(?:\$\s*\d+(?:,\d{3})*(?:\.\d+)?|\b\d+(?:\.\d+)?\s*(?:BTC|XMR|ETH|USD|EUR)\b)",
    re.IGNORECASE,
)

IGNORED_EMAIL_DOMAINS = {"example.com", "example.org", "domain.com", "test.com", "localhost"}
IGNORED_HANDLES = {"telegram", "channel", "gmail", "protonmail", "proton", "outlook", "onionmail"}


def _add(items: list[str], value: str) -> None:
    if value not in items:
        items.append(value)


def extract_iocs(text: str) -> ExtractedIOCs:
    result = ExtractedIOCs()
    if not text:
        return result

    for match in RE_ONION.findall(text):
        cleaned = match.strip().rstrip(".,;:)")
        if cleaned.lower() not in (item.lower() for item in result.onion_urls):
            result.onion_urls.append(cleaned)

    for regex in (RE_BTC_LEGACY, RE_BTC_BECH32):
        for match in regex.findall(text):
            if is_valid_bitcoin_address(match):
                _add(result.bitcoin_addresses, match)

    for match in RE_XMR.findall(text):
        _add(result.monero_addresses, match)
    for match in RE_ETH.findall(text):
        _add(result.ethereum_addresses, match)
    for match in RE_TOX.findall(text):
        _add(result.tox_ids, match)

    for match in RE_EMAIL.findall(text):
        email = match.strip().rstrip(".,;:)").lower()
        if email.split("@")[-1] not in IGNORED_EMAIL_DOMAINS:
            _add(result.emails, email)

    for match in RE_TELEGRAM.findall(text):
        if match.lower() not in IGNORED_HANDLES:
            _add(result.telegram_handles, f"@{match}")

    for match in RE_VICTIM_ID.findall(text):
        _add(result.victim_ids, match.strip())

    # STOP/Djvu style: "Your personal ID:" on one line, the ID on the next non-empty line.
    lines = [line.strip() for line in text.splitlines()]
    for index, line in enumerate(lines):
        if RE_ID_HEADER.search(line):
            for following in lines[index + 1 : index + 3]:
                if following:
                    if re.fullmatch(r"[0-9A-Za-z]{8,64}", following):
                        _add(result.victim_ids, following)
                    break

    for vid in result.victim_ids:
        if vid.lower().endswith("t1"):
            result.stop_djvu_offline_key = True
            result.notes.append(
                f"Personal ID '{vid}' ends in 't1'. For STOP/Djvu this usually means an OFFLINE ID. "
                "Emsisoft's free decryptor works only if it holds that variant's offline key, so it is "
                "worth trying but not guaranteed."
            )
            break

    for match in RE_DEADLINE.findall(text):
        _add(result.deadlines, match.strip().lower())
    for match in RE_RANSOM_AMOUNT.findall(text):
        _add(result.ransom_amounts, match.strip())

    return result
