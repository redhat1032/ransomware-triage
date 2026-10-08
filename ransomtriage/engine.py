"""Core triage: observe files, match them against the catalog and build a report."""

from __future__ import annotations

import fnmatch
import hashlib
import re
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path

from .catalog import Catalog, Decryptor, Signature, load_catalog, normalize_text
from .crypto_analysis import EntropyProfile, FilePairMatch, find_original_file_pairs, inspect_file_entropy
from .extractor import ExtractedIOCs, extract_iocs

#: Never read more than this many bytes of any single file for text analysis.
MAX_TEXT_BYTES = 512_000
#: Files larger than this are hashed only when explicitly small enough.
MAX_HASH_BYTES = 25_000_000
MAX_SCAN_FILES = 10_000
MAX_EXCERPT_CHARS = 20_000

#: Minimum score for a family to be listed as a candidate.
CANDIDATE_THRESHOLD = 5
#: Evidence kinds that come from the text of a ransom note. A verdict requires at least one.
NOTE_TEXT_KINDS = frozenset({"note-keyword", "family-name"})

# Generic ransom-note language. A file must contain at least NOTE_CUE_MINIMUM of these before a
# family *name* found in it counts as evidence (so a README that mentions "cactus" is ignored).
NOTE_CUES = (
    r"encrypt(?:ed|ion)?",
    r"decrypt(?:ion|or|ed)?",
    r"ransom",
    r"bitcoin|btc|monero|xmr",
    r"tor browser|\.onion",
    r"your (?:important )?files",
    r"(?:personal|decryption|victim|unique) id",
    r"leak(?:ed)? (?:site|blog|portal)|publish(?:ed)? (?:your )?data",
    r"private key",
)
NOTE_CUE_MINIMUM = 2
_NOTE_CUE_RES = tuple(re.compile(rf"(?<![a-z0-9]){cue}(?![a-z0-9])") for cue in NOTE_CUES)


@dataclass(frozen=True)
class Evidence:
    kind: str
    value: str
    source: str
    weight: int
    count: int = 1


@dataclass
class FamilyMatch:
    family: str
    aliases: tuple[str, ...]
    decryptability_status: str
    exfiltration_risk: str
    score: int = 0
    evidence: list[Evidence] = field(default_factory=list)
    decryptors: list[Decryptor] = field(default_factory=list)
    summary: str = ""
    preserve_advice: str = ""
    sources: tuple[str, ...] = ()
    last_verified: str = ""
    note: str = ""

    @property
    def confirmed(self) -> bool:
        """True when ransom-note text (not just a file name/extension) supports this family."""
        return any(item.kind in NOTE_TEXT_KINDS for item in self.evidence)

    @property
    def confidence(self) -> str:
        if not self.confirmed:
            return "unconfirmed"
        if self.score >= 12:
            return "high"
        if self.score >= 6:
            return "medium"
        return "low"

    @property
    def verdict(self) -> str:
        status = self.decryptability_status
        if status == "AVAILABLE":
            return "FREE DECRYPTOR LISTED"
        if status == "PARTIAL_OR_OFFLINE_ONLY":
            return "CONDITIONALLY RECOVERABLE"
        if status == "LEAKED_KEY_SET":
            return "SOME KEYS RECOVERED"
        if status == "WIPER":
            return "SUSPECTED WIPER (NO KEY EXISTS)"
        return "NO FREE DECRYPTOR KNOWN"


@dataclass(frozen=True)
class FileObservation:
    path: str
    size: int
    sha256: str | None
    text_excerpt: str | None
    note_like: bool = False


@dataclass(frozen=True)
class ChecklistItem:
    step: str
    cisa: str
    nist: str


@dataclass
class TriageReport:
    target: str
    matches: list[FamilyMatch]
    observations: list[FileObservation]
    iocs: ExtractedIOCs
    entropy_profiles: list[EntropyProfile]
    file_pairs: list[FilePairMatch]
    warnings: list[str]
    checklist: list[ChecklistItem]
    general_resources: tuple[Decryptor, ...]
    summary_verdict: str
    catalog_updated: str = ""

    @property
    def confirmed_matches(self) -> list[FamilyMatch]:
        return [m for m in self.matches if m.confirmed]


def scan_path(target: Path, catalog: Catalog | None = None, check_entropy: bool = True) -> TriageReport:
    catalog = catalog or load_catalog()
    target = target.expanduser().resolve()
    paths = _collect_paths(target)
    warnings: list[str] = []
    if len(paths) >= MAX_SCAN_FILES:
        warnings.append(f"Scan stopped at {MAX_SCAN_FILES} files. Narrow the target for a complete pass.")

    observations = [_observe_file(path) for path in paths]
    note_text = "\n".join(obs.text_excerpt for obs in observations if obs.text_excerpt and obs.note_like)
    iocs = extract_iocs(note_text)

    entropy_profiles: list[EntropyProfile] = []
    if check_entropy:
        for path in paths[:20]:
            profile = inspect_file_entropy(path)
            if profile:
                entropy_profiles.append(profile)

    file_pairs = find_original_file_pairs(paths)
    matches = _match_observations(observations, catalog)

    confirmed = [m for m in matches if m.confirmed]
    if iocs.stop_djvu_offline_key and confirmed and confirmed[0].family == "STOP/Djvu":
        confirmed[0].note = (
            "Personal ID ends in 't1' (usually an OFFLINE ID). Try Emsisoft's STOP Djvu decryptor: it works only "
            "if Emsisoft holds this variant's offline key, so success is possible but not guaranteed."
        )

    warnings.extend(_scam_warnings(observations))
    if matches and not confirmed:
        warnings.append(
            "File names/extensions resemble a known family, but no ransom-note text confirmed it. "
            "Extensions are reused and spoofed; do not act on the family name alone."
        )
    warnings.extend(f"[IOC] {note}" for note in iocs.notes)

    return TriageReport(
        target=str(target),
        matches=matches,
        observations=observations,
        iocs=iocs,
        entropy_profiles=entropy_profiles,
        file_pairs=file_pairs,
        warnings=warnings,
        checklist=default_checklist(),
        general_resources=catalog.general_resources,
        summary_verdict=_summary_verdict(matches, iocs),
        catalog_updated=catalog.updated,
    )


def _collect_paths(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    if not target.exists():
        raise FileNotFoundError(f"Target does not exist: {target}")
    paths: list[Path] = []
    for path in sorted(target.rglob("*")):
        if path.is_file() and not path.is_symlink():
            paths.append(path)
            if len(paths) >= MAX_SCAN_FILES:
                break
    return paths


def _observe_file(path: Path) -> FileObservation:
    try:
        size = path.stat().st_size
    except OSError:
        return FileObservation(path=str(path), size=0, sha256=None, text_excerpt=None)
    sha256 = _sha256(path) if size <= MAX_HASH_BYTES else None
    text_excerpt = read_text_excerpt(path)
    return FileObservation(
        path=str(path),
        size=size,
        sha256=sha256,
        text_excerpt=text_excerpt,
        note_like=is_note_like(text_excerpt, path.name),
    )


def _sha256(path: Path) -> str | None:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def read_text_excerpt(path: Path, limit: int = MAX_TEXT_BYTES) -> str | None:
    """Return normalised text from the first *limit* bytes of *path*, or None for binary files.

    Only a bounded prefix is ever read, so multi-gigabyte files cannot exhaust memory.
    """
    try:
        with path.open("rb") as handle:
            raw = handle.read(limit)
    except OSError:
        return None
    if not raw:
        return None
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = raw.decode("utf-16", errors="replace")
    else:
        if b"\x00" in raw[:4096]:
            return None
        text = raw.decode("utf-8", errors="replace")
        if text.count("\ufffd") > max(16, len(text) // 20):
            return None
    cleaned = " ".join(text.split())
    return cleaned[:MAX_EXCERPT_CHARS] or None


_NOTE_NAME_HINT = re.compile(r"read.?me|restore|recover|decrypt|how.?to|instruction|warning|info\.hta", re.IGNORECASE)


def is_note_like(text: str | None, filename: str = "") -> bool:
    """Heuristic: does this text read like a ransom note (rather than ordinary documentation)?"""
    if not text:
        return False
    lowered = normalize_text(text)
    cues = sum(1 for cue in _NOTE_CUE_RES if cue.search(lowered))
    if cues >= NOTE_CUE_MINIMUM:
        return True
    return cues >= 1 and bool(_NOTE_NAME_HINT.search(filename))


@cache
def _word_re(phrase: str) -> re.Pattern[str]:
    return re.compile(rf"(?<![a-z0-9]){re.escape(phrase)}(?![a-z0-9])")


def _match_observations(observations: list[FileObservation], catalog: Catalog) -> list[FamilyMatch]:
    results: list[FamilyMatch] = []
    for signature in catalog.signatures:
        found: dict[tuple[str, str], Evidence] = {}
        for observation in observations:
            for kind, value, weight in _file_evidence(signature, observation):
                _record(found, kind, value, observation.path, weight)
            for kind, value, weight in _text_evidence(signature, observation):
                _record(found, kind, value, observation.path, weight)
        if not found:
            continue
        evidence = list(found.values())
        score = sum(item.weight for item in evidence)
        # Many files sharing one extension is stronger than a single stray file.
        score += sum(2 for item in evidence if item.kind == "extension" and item.count >= 3)
        match = FamilyMatch(
            family=signature.family,
            aliases=signature.aliases,
            decryptability_status=signature.decryptability_status,
            exfiltration_risk=signature.exfiltration_risk,
            score=score,
            evidence=evidence,
            decryptors=[catalog.decryptors[key] for key in signature.decryptors if key in catalog.decryptors],
            summary=signature.summary,
            preserve_advice=signature.preserve_advice,
            sources=signature.sources,
            last_verified=signature.last_verified,
        )
        if match.confirmed or score >= CANDIDATE_THRESHOLD:
            results.append(match)
    return sorted(results, key=lambda m: (m.confirmed, m.score), reverse=True)


def _record(found: dict[tuple[str, str], Evidence], kind: str, value: str, source: str, weight: int) -> None:
    key = (kind, value)
    if key in found:
        old = found[key]
        found[key] = Evidence(kind=kind, value=value, source=old.source, weight=old.weight, count=old.count + 1)
    else:
        found[key] = Evidence(kind=kind, value=value, source=source, weight=weight)


def _file_evidence(signature: Signature, observation: FileObservation) -> list[tuple[str, str, int]]:
    name = Path(observation.path).name.lower()
    hits: list[tuple[str, str, int]] = []
    for pattern in signature.note_filenames:
        if fnmatch.fnmatchcase(name, pattern):
            hits.append(("note-filename", pattern, 5))
    for ext in signature.extensions:
        if name.endswith(ext) and len(name) > len(ext):
            hits.append(("extension", ext, 4))
    for ext in signature.weak_extensions:
        if name.endswith(ext) and len(name) > len(ext):
            hits.append(("weak-extension", ext, 2))
    for pattern in signature.extension_patterns:
        if re.search(pattern, name):
            hits.append(("extension-pattern", pattern, 4))
    return hits


def _text_evidence(signature: Signature, observation: FileObservation) -> list[tuple[str, str, int]]:
    if not observation.text_excerpt:
        return []
    text = normalize_text(observation.text_excerpt)
    hits: list[tuple[str, str, int]] = []
    for phrase in signature.note_keywords:
        if _word_re(phrase).search(text):
            hits.append(("note-keyword", phrase, 6))
    if observation.note_like:
        for name in signature.self_names:
            if _word_re(name).search(text):
                hits.append(("family-name", name, 4))
    return hits


def _scam_warnings(observations: list[FileObservation]) -> list[str]:
    joined = " ".join(item.text_excerpt or "" for item in observations).lower()
    risky_claims = [
        "guaranteed recovery",
        "100% recovery",
        "exclusive decryptor",
        "pay us in bitcoin",
        "do not contact police",
        "price will double",
        "destroy your files forever",
        "no one else can help you",
    ]
    return [
        f"Pressure tactic detected: {claim!r}. Don't pay in a panic; check official decryptors and get IR help."
        for claim in risky_claims
        if claim in joined
    ]


def _summary_verdict(matches: list[FamilyMatch], iocs: ExtractedIOCs) -> str:
    confirmed = [m for m in matches if m.confirmed]
    if not confirmed:
        if matches:
            return (
                f"UNCONFIRMED: file names/extensions resemble {matches[0].family}, but no ransom-note text matched. "
                "No verdict given. Confirm with No More Ransom Crypto Sheriff or ID Ransomware."
            )
        return "UNKNOWN: no match in the local catalog. Check No More Ransom Crypto Sheriff or ID Ransomware."

    top = confirmed[0]
    status = top.decryptability_status
    if status == "AVAILABLE":
        return f"FREE DECRYPTOR LISTED for {top.family}. Check its limits and test on copies first."
    if status == "PARTIAL_OR_OFFLINE_ONLY":
        if top.family == "STOP/Djvu" and iocs.stop_djvu_offline_key:
            return (
                "CONDITIONALLY RECOVERABLE (STOP/Djvu): the personal ID ends in 't1' (likely an offline ID). "
                "Emsisoft's decryptor can help only if it holds this offline key."
            )
        return f"CONDITIONALLY RECOVERABLE ({top.family}): depends on variant, key type or file pairs."
    if status == "LEAKED_KEY_SET":
        return f"SOME KEYS RECOVERED ({top.family}): check your victim/decryption ID with the listed tool."
    if status == "WIPER":
        return f"SUSPECTED WIPER ({top.family}): no decryption key exists. Prioritise backup recovery."
    return f"NO FREE DECRYPTOR KNOWN for {top.family}. Do not pay unverified 'recovery' brokers."


def default_checklist() -> list[ChecklistItem]:
    """First-hour checklist, mapped to the CISA #StopRansomware Guide (Part 2) and NIST IR 8374 Rev. 1."""
    return [
        ChecklistItem(
            "Isolate affected systems: unplug network cables / disable Wi-Fi; take the network offline at the "
            "switch if many systems are hit. Power down only if you cannot disconnect.",
            "Steps 1-2",
            "RS.MI-01",
        ),
        ChecklistItem(
            "Do not wipe or reinstall. Where possible, capture memory and a disk image of a sample of affected "
            "systems before rebooting (some recovery, e.g. WannaCry, needs the original memory).",
            "Step 9",
            "DE.AE-02",
        ),
        ChecklistItem(
            "Preserve ransom notes, encrypted samples and logs. Do not rename or delete encrypted files; "
            "decryptors may need the original names and notes.",
            "Reporting list; Step 9",
            "DE.AE-02, RS.CO-03",
        ),
        ChecklistItem(
            "Check for a free decryptor (No More Ransom, the tools listed here) and ask law enforcement. Test any "
            "decryptor on COPIES first.",
            "Steps 10-11",
            "RC.RP-02",
        ),
        ChecklistItem(
            "Report and notify: CISA / FBI IC3 (US) or your national CERT/police, plus your IR plan contacts, "
            "insurer and legal counsel. Follow breach-notification rules if data was stolen.",
            "Steps 7-8",
            "RS.MA-01, RS.CO-02, RS.CO-03",
        ),
        ChecklistItem(
            "Hunt for how they got in and what they took: new admin accounts, VPN/RDP logins, remote-access tools, "
            "exfiltration tools such as Rclone.",
            "Steps 4, 6, 12-15",
            "DE.AE-04, RS.MI-02",
        ),
        ChecklistItem(
            "Restore only from verified offline backups after the environment is clean; reset credentials.",
            "Steps 16-17, 19",
            "RC.RP-01, RC.RP-03",
        ),
        ChecklistItem(
            "Be wary of 'recovery' firms that guarantee decryption; some simply pay the criminals. Authorities "
            "do not recommend paying, and payments can carry sanctions risk.",
            "Part 2 introduction",
            "DE.AE-04",
        ),
        ChecklistItem(
            "Document lessons learned and share indicators with CISA or your sector ISAC.",
            "Steps 20-21",
            "RS.CO-03, RC.CO-03",
        ),
    ]
