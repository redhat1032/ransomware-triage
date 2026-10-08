"""Local-first ransomware incident triage and victim guidance toolkit."""

from .catalog import Catalog, Decryptor, Signature, load_catalog
from .crypto_analysis import calculate_entropy, inspect_file_entropy
from .engine import TriageReport, scan_path
from .extractor import ExtractedIOCs, extract_iocs

__version__ = "0.3.0"
__all__ = [
    "Catalog",
    "Decryptor",
    "Signature",
    "load_catalog",
    "calculate_entropy",
    "inspect_file_entropy",
    "TriageReport",
    "scan_path",
    "ExtractedIOCs",
    "extract_iocs",
]
