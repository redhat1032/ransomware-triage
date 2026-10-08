from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from ransomtriage.catalog import VALID_STATUSES, load_catalog

RAW = json.loads((Path(__file__).resolve().parent.parent / "ransomtriage" / "signatures.json").read_text("utf-8"))
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class CatalogTest(unittest.TestCase):
    def test_catalog_loads(self) -> None:
        catalog = load_catalog()
        self.assertGreaterEqual(len(catalog.signatures), 25)
        self.assertGreaterEqual(len(catalog.decryptors), 15)
        self.assertGreaterEqual(len(catalog.general_resources), 5)

    def test_references_and_statuses(self) -> None:
        catalog = load_catalog()
        for sig in catalog.signatures:
            self.assertIn(sig.decryptability_status, VALID_STATUSES, sig.family)
            self.assertIn(sig.exfiltration_risk, {"high", "moderate", "low", "unknown"})
            for dec_id in sig.decryptors:
                self.assertIn(dec_id, catalog.decryptors, f"{sig.family} -> {dec_id}")
            if sig.decryptability_status == "NONE_KNOWN":
                self.assertEqual(sig.decryptors, (), f"{sig.family} says NONE_KNOWN but lists decryptors")
                self.assertIn("no free decryptor", sig.summary.lower(), sig.family)

    def test_every_entry_is_sourced_and_dated(self) -> None:
        for item in RAW["decryptors"]:
            self.assertTrue(item["source_urls"], item["id"])
            self.assertRegex(item["last_verified"], DATE)
            self.assertTrue(item["url"].startswith("https://"), item["id"])
        for item in RAW["signatures"]:
            self.assertTrue(item["sources"], item["family"])
            self.assertRegex(item["last_verified"], DATE)

    def test_no_generic_markers(self) -> None:
        banned_names = {"readme.txt", "read_me.txt", "readme.md", "info.txt"}
        banned_words = {"play", "tor", "onion", "encrypted", "decrypt", "bitcoin"}
        for item in RAW["signatures"]:
            for name in item["note_filenames"]:
                self.assertNotIn(name.lower(), banned_names, item["family"])
            for word in item["note_keywords"] + item["self_names"]:
                self.assertNotIn(word.lower(), banned_words, item["family"])

    def test_corrected_facts(self) -> None:
        catalog = load_catalog()
        by_family = {sig.family: sig for sig in catalog.signatures}
        self.assertIn("npa-phobos-8base", by_family["Phobos / 8Base"].decryptors)
        self.assertIn("March 2024", catalog.decryptors["avast-mallox"].notes)
        for family in ("BlackCat / ALPHV", "DeadBolt"):
            self.assertNotIn("jp-police-lockbit-checker", by_family[family].decryptors)
        self.assertNotIn("kisa-hive", by_family["Hunters International"].decryptors)
        self.assertEqual(by_family["Destructive wiper (fake ransomware)"].decryptability_status, "WIPER")
        self.assertEqual(
            catalog.decryptors["srlabs-black-basta-buster"].url, "https://github.com/srlabs/black-basta-buster"
        )
        for family in ("Qilin", "RansomHub", "Cactus", "Clop"):
            self.assertIn(family, by_family)


if __name__ == "__main__":
    unittest.main()
