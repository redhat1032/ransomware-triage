"""Bitcoin address checksum validation (Base58Check and Bech32/Bech32m), stdlib only."""

from __future__ import annotations

import hashlib

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_CONST = 1
_BECH32M_CONST = 0x2BC830A3


def is_valid_base58check(address: str) -> bool:
    """True for a mainnet P2PKH ("1...") or P2SH ("3...") address with a valid checksum."""
    if not 26 <= len(address) <= 35:
        return False
    num = 0
    for char in address:
        index = _B58.find(char)
        if index < 0:
            return False
        num = num * 58 + index
    pad = len(address) - len(address.lstrip("1"))
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    raw = b"\x00" * pad + body
    if len(raw) != 25:
        return False
    payload, checksum = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum:
        return False
    return payload[0] in (0x00, 0x05)


def _polymod(values: list[int]) -> int:
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if (top >> i) & 1 else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convertbits(data: list[int], frombits: int, tobits: int) -> list[int] | None:
    acc = bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def is_valid_bech32(address: str) -> bool:
    """True for a mainnet SegWit address (BIP173 v0 / BIP350 v1+) with a valid checksum."""
    if address.lower() != address and address.upper() != address:
        return False
    address = address.lower()
    if not 14 <= len(address) <= 90 or not address.startswith("bc1"):
        return False
    hrp, data_part = "bc", address[3:]
    if any(c not in _B32 for c in data_part) or len(data_part) < 7:
        return False
    data = [_B32.find(c) for c in data_part]
    const = _polymod(_hrp_expand(hrp) + data)
    witver = data[0]
    if witver == 0 and const != _BECH32_CONST:
        return False
    if witver != 0 and const != _BECH32M_CONST:
        return False
    if witver > 16:
        return False
    program = _convertbits(data[1:-6], 5, 8)
    if program is None or not 2 <= len(program) <= 40:
        return False
    return not (witver == 0 and len(program) not in (20, 32))


def is_valid_bitcoin_address(address: str) -> bool:
    if address[:3].lower() == "bc1":
        return is_valid_bech32(address)
    return is_valid_base58check(address)
