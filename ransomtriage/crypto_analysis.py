from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class EntropyProfile:
    path: str
    overall_entropy: float
    head_entropy: float
    tail_entropy: float
    is_intermittent: bool
    classification: str


@dataclass(frozen=True)
class FilePairMatch:
    encrypted_path: str
    original_path: str
    encrypted_size: int
    original_size: int


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte sequence (0.0 to 8.0)."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def inspect_file_entropy(path: Path, sample_size: int = 65536) -> EntropyProfile | None:
    """Analyze entropy across head, middle, and tail of a file."""
    try:
        size = path.stat().st_size
    except OSError:
        return None

    if size < 512:
        return None

    try:
        with path.open("rb") as f:
            head = f.read(min(sample_size, size))
            if size > sample_size:
                f.seek(size - min(sample_size, size))
                tail = f.read(min(sample_size, size))
            else:
                tail = head
    except OSError:
        return None

    head_ent = calculate_entropy(head)
    tail_ent = calculate_entropy(tail)
    overall_ent = round((head_ent + tail_ent) / 2.0, 4)

    # Intermittent encryption detection: significant divergence between regions
    # or high head (> 7.9) with markedly lower tail (< 6.8)
    is_intermittent = (head_ent >= 7.85 and tail_ent <= 6.8) or (tail_ent >= 7.85 and head_ent <= 6.8)

    if overall_ent >= 7.95:
        classification = "Likely Encrypted (Full)"
    elif is_intermittent:
        classification = "Intermittent / Partial Encryption"
    elif overall_ent >= 7.4:
        classification = "High Entropy (Compressed / Encrypted)"
    else:
        classification = "Normal / Low Entropy (Plaintext or Structured)"

    return EntropyProfile(
        path=str(path),
        overall_entropy=overall_ent,
        head_entropy=head_ent,
        tail_entropy=tail_ent,
        is_intermittent=is_intermittent,
        classification=classification,
    )


def find_original_file_pairs(paths: list[Path]) -> list[FilePairMatch]:
    """Identify if unencrypted copies of encrypted files exist in the set."""
    path_map = {p.resolve(): p for p in paths if p.is_file()}
    pairs: list[FilePairMatch] = []

    for path in paths:
        # Check if stripping known extension leaves an existing original file
        parent = path.parent
        name = path.name
        # If double extension like file.docx.djvu or file.pdf.locked
        suffixes = path.suffixes
        if len(suffixes) >= 2:
            base_name = name[: -len(suffixes[-1])]
            candidate = (parent / base_name).resolve()
            if candidate in path_map and candidate != path.resolve():
                pairs.append(
                    FilePairMatch(
                        encrypted_path=str(path.resolve()),
                        original_path=str(candidate.resolve()),
                        encrypted_size=path.stat().st_size,
                        original_size=candidate.stat().st_size,
                    )
                )

    return pairs
