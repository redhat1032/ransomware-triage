from __future__ import annotations

import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from ransomtriage import __version__
from ransomtriage.cli import main

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"

try:
    import yara  # type: ignore
except ImportError:  # pragma: no cover - optional
    yara = None


def run(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class CLITest(unittest.TestCase):
    def test_version(self) -> None:
        with self.assertRaises(SystemExit):
            run("--version")

    def test_version_string(self) -> None:
        self.assertEqual(__version__, "0.3.0")

    def test_list_families(self) -> None:
        code, out, _ = run("list-families", "--search", "akira")
        self.assertEqual(code, 0)
        self.assertIn("Akira", out)
        self.assertIn("Avast Akira Decryptor", out)

    def test_list_families_json(self) -> None:
        code, out, _ = run("list-families", "--format", "json")
        self.assertEqual(code, 0)
        self.assertGreaterEqual(len(json.loads(out)), 25)

    def test_extract_json(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            note = Path(td) / "ransom.txt"
            note.write_text(
                "Send 0.5 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\nattacker@protonmail.com\n"
                "Personal ID: 0123456789ABCDEFt1",
                encoding="utf-8",
            )
            code, out, _ = run("extract", str(note), "--format", "json")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertIn("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", data["bitcoin_addresses"])
        self.assertIn("attacker@protonmail.com", data["emails"])
        self.assertTrue(data["stop_djvu_offline_key"])

    def test_scan_exports(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            shutil.copytree(EXAMPLES / "lockbit3", Path(td) / "case")
            iocs, rule = Path(td) / "iocs.txt", Path(td) / "rule.yar"
            code, out, _ = run("scan", str(Path(td) / "case"), "--export-iocs", str(iocs), "--export-yara", str(rule))
            self.assertEqual(code, 0)
            self.assertIn("LockBit", out)
            self.assertIn("samplexampleonionaddressfortestingonly234567abcdefghijka.onion", iocs.read_text("utf-8"))
            self.assertIn("rule RansomTriage_LockBit", rule.read_text("utf-8"))

    def test_identify_is_single_file(self) -> None:
        code, out, _ = run("identify", str(EXAMPLES / "stop-djvu" / "_readme.txt"), "--format", "markdown")
        self.assertEqual(code, 0)
        self.assertIn("# Ransomware Triage Report", out)
        self.assertIn("STOP/Djvu", out)
        self.assertNotIn("entropy", out.lower().split("## warnings")[0])
        code, _, err = run("identify", str(EXAMPLES / "stop-djvu"))
        self.assertEqual(code, 2)
        self.assertIn("single file", err)

    def test_bare_path_means_scan(self) -> None:
        code, out, _ = run(str(EXAMPLES / "wannacry"), "--format", "json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["confirmed_families"], ["WannaCry"])


class YaraTest(unittest.TestCase):
    def test_no_indicators_skips_yara(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            Path(td, "note.txt").write_text("hello world", encoding="utf-8")
            rule = Path(td) / "rule.yar"
            code, _, err = run("scan", str(Path(td) / "note.txt"), "--export-yara", str(rule))
            self.assertEqual(code, 0)
            self.assertFalse(rule.exists())
            self.assertIn("skipped", err)

    def test_generated_rules_are_well_formed(self) -> None:
        from ransomtriage.engine import scan_path
        from ransomtriage.yara_export import generate_yara_rule

        for case in ("lockbit3", "stop-djvu", "wannacry"):
            source = generate_yara_rule(scan_path(EXAMPLES / case, check_entropy=False))
            self.assertIsNotNone(source)
            self.assertIn("any of them", source)
            self.assertRegex(source, r'\$\w+_1 = "')
            if yara is not None:
                yara.compile(source=source)

    @unittest.skipIf(yara is None, "yara-python not installed")
    def test_quotes_and_backslashes_compile(self) -> None:
        from ransomtriage.yara_export import _escape

        escaped = _escape('say "hi" C:\\temp\\x é')
        yara.compile(source='rule t { strings: $a = "' + escaped + '" condition: $a }')


if __name__ == "__main__":
    unittest.main()
