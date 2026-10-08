#!/usr/bin/env python3
"""Check that every URL in the catalog (and the README) still resolves. Maintainer tool; needs network."""

from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UA = "Mozilla/5.0 (compatible; ransomtriage-url-check)"


def catalog_urls() -> set[str]:
    data = json.loads((ROOT / "ransomtriage" / "signatures.json").read_text("utf-8"))
    urls: set[str] = set()
    for item in data["general_resources"]:
        urls.add(item["url"])
    for item in data["decryptors"]:
        urls.add(item["url"])
        urls.update(item["source_urls"])
    for item in data["signatures"]:
        urls.update(item["sources"])
    readme = (ROOT / "README.md").read_text("utf-8")
    urls.update(u for u in re.findall(r"https://[^\s)>\]\"']+", readme) if "img.shields.io" not in u)
    return {u.split("#")[0] for u in urls}


def check(url: str) -> tuple[str, str]:
    request = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return url, str(response.status)
    except urllib.error.HTTPError as exc:
        return url, f"HTTP {exc.code}"
    except Exception as exc:  # noqa: BLE001 - report anything
        return url, f"ERROR {type(exc).__name__}: {exc}"


def main() -> int:
    bad = 0
    with ThreadPoolExecutor(8) as pool:
        for url, status in sorted(pool.map(check, sorted(catalog_urls()))):
            ok = status.startswith("2")
            bad += not ok
            print(f"{'OK ' if ok else 'BAD'} {status:<10} {url}")
    print(f"\n{bad} problem URL(s). Some sites block scripts (403); confirm those in a browser.")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
