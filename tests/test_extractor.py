from __future__ import annotations

import unittest

from ransomtriage.btc import _B32, _convertbits, _hrp_expand, _polymod, is_valid_bech32, is_valid_bitcoin_address
from ransomtriage.extractor import extract_iocs


def _to5(data: bytes) -> list[int]:
    return _convertbits(list(data), 8, 5) or [] if len(data) * 8 % 5 == 0 else _pad5(data)


def _pad5(data: bytes) -> list[int]:
    acc = bits = 0
    out = []
    for byte in data:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append((acc >> bits) & 31)
    if bits:
        out.append((acc << (5 - bits)) & 31)
    return out


def _encode(data: list[int], const: int) -> str:
    polymod = _polymod(_hrp_expand("bc") + data + [0] * 6) ^ const
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return "bc1" + "".join(_B32[d] for d in data + checksum)


class BitcoinValidationTest(unittest.TestCase):
    VALID = [
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",  # P2PKH (genesis)
        "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",  # P2SH (BIP13 example)
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",  # P2WPKH
        "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",  # BIP173 test vector (upper case)
        "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297",  # BIP350 taproot
    ]
    INVALID = [
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb",  # bad base58 checksum
        "12t9YDPgwH557qDjbf94KQBzWBPaKcStCx",  # looks right, checksum fails
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdx",  # bad bech32 checksum
        "bc1qW508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",  # mixed case
        "1111111111111111111111111111111111",
    ]

    def test_valid(self) -> None:
        for address in self.VALID:
            self.assertTrue(is_valid_bitcoin_address(address), address)

    def test_invalid(self) -> None:
        for address in self.INVALID:
            self.assertFalse(is_valid_bitcoin_address(address), address)

    def test_bech32m_rejected_for_v0(self) -> None:
        # A v0 program checksummed with the bech32m constant must fail (BIP350), and vice versa.
        program = [0] + _to5(bytes(range(20)))
        self.assertTrue(is_valid_bech32(_encode(program, 1)))
        self.assertFalse(is_valid_bech32(_encode(program, 0x2BC830A3)))
        taproot = [1] + _to5(bytes(range(32)))
        self.assertTrue(is_valid_bech32(_encode(taproot, 0x2BC830A3)))
        self.assertFalse(is_valid_bech32(_encode(taproot, 1)))

    def test_extractor_drops_bad_checksums(self) -> None:
        iocs = extract_iocs("Pay to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb or 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        self.assertEqual(iocs.bitcoin_addresses, ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"])


class ExtractorTest(unittest.TestCase):
    def test_wallets(self) -> None:
        text = (
            "Pay 0.5 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa or bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq.\n"
            "Monero: 44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"
        )
        iocs = extract_iocs(text)
        self.assertIn("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", iocs.bitcoin_addresses)
        self.assertIn("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", iocs.bitcoin_addresses)
        self.assertEqual(len(iocs.monero_addresses), 1)

    def test_onion_tox_email_telegram(self) -> None:
        text = (
            "Portal: http://samplexampleonionaddressfortestingonly234567abcdefghijka.onion/chat\n"
            "TOX: 76A2280FE6A34F5C0DFBEF11B9302322DB956E85B242171E9762FF9214D16773EB2FE0CECB0B\n"
            "Email unlockfiles@protonmail.com or @lockbit_support on Telegram, or t.me/decrypt_help."
        )
        iocs = extract_iocs(text)
        self.assertTrue(any(".onion" in u for u in iocs.onion_urls))
        self.assertEqual(len(iocs.tox_ids), 1)
        self.assertIn("unlockfiles@protonmail.com", iocs.emails)
        self.assertEqual(iocs.telegram_handles, ["@lockbit_support", "@decrypt_help"])

    def test_telegram_ignores_email_domains(self) -> None:
        text = "Write to restore@company.com, backup@mail.example.org, or (alt) @company.com and admin@onionmail.org"
        self.assertEqual(extract_iocs(text).telegram_handles, [])

    def test_stop_offline_id_is_flagged_but_not_promised(self) -> None:
        text = "Your personal ID:\n0123456789ABCDEF0123456789ABCDEFt1\nPrice is $980. Discount 50% in 72 hours."
        iocs = extract_iocs(text)
        self.assertTrue(iocs.stop_djvu_offline_key)
        self.assertIn("$980", iocs.ransom_amounts)
        self.assertTrue(any("72 hours" in d for d in iocs.deadlines))
        self.assertTrue(any("not guaranteed" in note for note in iocs.notes))
        self.assertFalse(any("100%" in note for note in iocs.notes))

    def test_online_id_not_flagged(self) -> None:
        iocs = extract_iocs("Your personal ID:\n0123456789ABCDEF0123456789ABCDEFonline\n")
        self.assertFalse(iocs.stop_djvu_offline_key)

    def test_hashes_are_not_victim_ids(self) -> None:
        iocs = extract_iocs("md5:\nd41d8cd98f00b204e9800998ecf8427e\nid: config_value_123")
        self.assertEqual(iocs.victim_ids, [])


if __name__ == "__main__":
    unittest.main()
