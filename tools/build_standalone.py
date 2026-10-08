#!/usr/bin/env python3
"""Build a single-file portable zipapp (dist/ransomtriage.pyz). Pure stdlib; runs on Python 3.9+."""

from __future__ import annotations

import shutil
import tempfile
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"
SOURCE = ROOT / "ransomtriage"


def build_pyz() -> Path:
    DIST.mkdir(exist_ok=True)
    out_file = DIST / "ransomtriage.pyz"

    with tempfile.TemporaryDirectory() as td:
        build_dir = Path(td) / "app"
        build_dir.mkdir()
        shutil.copytree(SOURCE, build_dir / "ransomtriage", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        (build_dir / "__main__.py").write_text(
            "import sys\nfrom ransomtriage.cli import main\n\nif __name__ == '__main__':\n    sys.exit(main())\n",
            encoding="utf-8",
        )
        zipapp.create_archive(source=build_dir, target=out_file, interpreter="/usr/bin/env python3", compressed=True)

    out_file.chmod(0o755)
    print(f"[+] Built {out_file} ({out_file.stat().st_size:,} bytes)")
    print(f"    Run with: python3 {out_file.relative_to(ROOT)} --help")
    return out_file


if __name__ == "__main__":
    build_pyz()
