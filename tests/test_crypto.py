from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from ransomtriage.crypto_analysis import calculate_entropy, find_original_file_pairs, inspect_file_entropy


class CryptoAnalysisTest(unittest.TestCase):
    def test_calculate_entropy(self) -> None:
        zeros = b"\x00" * 1024
        self.assertEqual(calculate_entropy(zeros), 0.0)
        random_bytes = os.urandom(4096)
        ent = calculate_entropy(random_bytes)
        self.assertGreater(ent, 7.8)

    def test_inspect_file_entropy_and_intermittent(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            fpath = Path(td) / "sample.bin"
            head = os.urandom(65536)
            tail = b"\x00" * 65536
            fpath.write_bytes(head + tail)
            profile = inspect_file_entropy(fpath)
            self.assertIsNotNone(profile)
            self.assertTrue(profile.is_intermittent)
            self.assertIn("Intermittent", profile.classification)

    def test_find_original_file_pairs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            orig = tdp / "important.docx"
            orig.write_text("Secret text", encoding="utf-8")
            enc = tdp / "important.docx.djvu"
            enc.write_bytes(b"\x99" * 128)
            paths = [orig, enc]
            pairs = find_original_file_pairs(paths)
            self.assertEqual(len(pairs), 1)
            self.assertEqual(pairs[0].original_path, str(orig.resolve()))
            self.assertEqual(pairs[0].encrypted_path, str(enc.resolve()))


if __name__ == "__main__":
    unittest.main()
