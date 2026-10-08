from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ransomtriage import engine
from ransomtriage.engine import read_text_excerpt, scan_path

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _write(directory: str, name: str, text: str) -> Path:
    path = Path(directory) / name
    path.write_text(text, encoding="utf-8")
    return path


class EngineTest(unittest.TestCase):
    def test_stop_fixture(self) -> None:
        report = scan_path(EXAMPLES / "stop-djvu")
        top = report.matches[0]
        self.assertEqual(top.family, "STOP/Djvu")
        self.assertTrue(top.confirmed)
        self.assertIn(top.confidence, {"medium", "high"})
        self.assertTrue(any(d.provider == "Emsisoft" for d in top.decryptors))

    def test_lockbit_and_wannacry_fixtures(self) -> None:
        self.assertEqual(scan_path(EXAMPLES / "lockbit3").confirmed_matches[0].family, "LockBit")
        wannacry = scan_path(EXAMPLES / "wannacry")
        self.assertEqual(wannacry.confirmed_matches[0].family, "WannaCry")
        self.assertIn("13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94", wannacry.iocs.bitcoin_addresses)

    def test_stop_t1_is_conditional_not_guaranteed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            note = _write(
                td,
                "_readme.txt",
                "ATTENTION!\nDon't worry my friend, you can return all your files!\n"
                "Your personal ID:\n99887766554433221100t1\n",
            )
            report = scan_path(note)
        self.assertTrue(report.iocs.stop_djvu_offline_key)
        top = report.matches[0]
        self.assertEqual(top.family, "STOP/Djvu")
        self.assertEqual(top.decryptability_status, "PARTIAL_OR_OFFLINE_ONLY")
        self.assertIn("CONDITIONALLY RECOVERABLE", report.summary_verdict)
        self.assertNotIn("100%", report.summary_verdict + top.note)

    def test_harmless_readme_is_not_ransomware(self) -> None:
        """Regression: generic words (play, tor, onion) and a README file name must not produce a verdict."""
        with tempfile.TemporaryDirectory() as td:
            _write(
                td,
                "readme.txt",
                "My Cactus Garden Media Player\n\nPress play to start the slideshow. Advanced users can route "
                "updates through Tor; see the onion routing FAQ. Medusa and Akira are my cats. "
                "Contact: help@company.com or @company.com. Version 2, released 3 days ago.",
            )
            _write(td, "README.md", "# Project\nRun `make play`. The tor proxy is optional.")
            _write(td, "notes.txt", "Shopping list: blackcat figurine, clop shoes, 12 days of play.")
            report = scan_path(Path(td))
        self.assertEqual(report.matches, [])
        self.assertTrue(report.summary_verdict.startswith("UNKNOWN"))
        self.assertEqual(report.iocs.telegram_handles, [])

    def test_extension_only_is_unconfirmed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            for index in range(3):
                Path(td, f"doc{index}.docx.akira").write_bytes(os.urandom(600))
            report = scan_path(Path(td), check_entropy=False)
        self.assertTrue(report.matches)
        self.assertEqual(report.matches[0].family, "Akira")
        self.assertFalse(report.matches[0].confirmed)
        self.assertEqual(report.confirmed_matches, [])
        self.assertTrue(report.summary_verdict.startswith("UNCONFIRMED"))

    def test_whole_word_matching(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            note = _write(
                td,
                "how_to_decrypt.txt",
                "Your files are encrypted. Pay in bitcoin. Contact the hivemind team. Playground rules.",
            )
            report = scan_path(note)
        self.assertNotIn("Hive", [m.family for m in report.confirmed_matches])

    def test_unknown_gets_resources(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            report = scan_path(_write(td, "note.txt", "hello world"))
        self.assertEqual(report.matches, [])
        self.assertTrue(report.general_resources)

    def test_scam_warning(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            report = scan_path(_write(td, "note.txt", "100% recovery! Pay us in bitcoin. Price will double."))
        self.assertTrue(any("100% recovery" in w for w in report.warnings))

    def test_checklist_is_mapped(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            report = scan_path(_write(td, "x.txt", "x"))
        self.assertTrue(all(item.cisa and item.nist for item in report.checklist))


class LargeFileTest(unittest.TestCase):
    def test_reads_only_a_bounded_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            big = Path(td) / "readme.txt"
            with big.open("wb") as handle:  # sparse 64 MB text-looking file
                handle.write(b"Your files are encrypted. " * 400)
                handle.seek(64 * 1024 * 1024)
                handle.write(b"end")
            with mock.patch.object(Path, "read_bytes", side_effect=AssertionError("whole-file read")):
                excerpt = read_text_excerpt(big, limit=4096)
                self.assertIsNotNone(excerpt)
                self.assertLessEqual(len(excerpt), 4096)
                report = scan_path(big, check_entropy=False)
        self.assertEqual(report.observations[0].size, 64 * 1024 * 1024 + 3)
        self.assertLessEqual(len(report.observations[0].text_excerpt or ""), engine.MAX_EXCERPT_CHARS)


if __name__ == "__main__":
    unittest.main()
