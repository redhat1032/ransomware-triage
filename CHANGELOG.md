# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Project
- Added `release.yml`: builds the sdist and wheel, runs `twine check --strict`, and publishes to PyPI with Trusted
  Publishing (OIDC, `pypi` environment). Runs on `release: published` or a manual dispatch with a tag input.
- CI uses current Node 24 actions (`actions/checkout` v7, `actions/setup-python` v7), pinned to commit SHAs, with
  credentials not persisted.

## [0.3.0] - 2026-10-08

First public release.

### Catalog (data corrections)
- Every decryptor and family entry now has source URLs and a `last_verified` date (2026-10-08); all decryptor URLs were checked.
- Phobos/8Base: added the National Police Agency of Japan decryptor (via No More Ransom).
- Mallox: the Avast decryptor is limited to variants from before the March 2024 fix; added the early TargetCompany decryptor.
- BlackCat/ALPHV and DeadBolt: removed the wrong LockBit decryptor link. BlackCat now notes the FBI's law-enforcement-only tool; DeadBolt notes the 155 keys recovered by Dutch police.
- Hunters International split from Hive. Hive decryptors do not apply to it.
- Wipers (WhisperGate, HermeticWiper, CaddyWiper) moved to their own "Destructive wiper (fake ransomware)" category.
- Honest wording for STOP/Djvu `t1` IDs (likely offline, not guaranteed) and WannaCry/wanakiwi (only before reboot).
- Fixed dead links, including SR Labs' Black Basta Buster (github.com/srlabs/black-basta-buster).
- Added Qilin, RansomHub, Cactus, Clop, Medusa, Makop and Mallox/TargetCompany entries using indicators from cited sources.
- Families with no known free decryptor now say so explicitly.
- Added `tools/build_catalog.py` (sourced catalog generator) and `tools/verify_urls.py` (link checker).

### Fewer false positives
- Whole-word matching. Generic markers such as `play`, `tor`, `onion` and a bare `readme.txt` are no longer used as evidence.
- A verdict now needs ransom-note text evidence. File names and extensions alone give an UNCONFIRMED candidate.
- A family name only counts inside text that reads like a ransom note.
- Added a regression test for a harmless README.

### Fixes
- Large files: at most 512 KB per file is read for text analysis (it used to read whole files into memory).
- YARA export: rules always compile. Export is skipped when there is nothing to match, instead of writing an invalid rule.
- Telegram pattern no longer matches email domains (`user@company.com`).
- Bitcoin addresses are validated with Base58Check and Bech32/Bech32m checksums.
- Onion addresses must be valid v3 (56-char) or legacy v2 (16-char) names.
- Victim IDs: a bare `id:` is no longer treated as a victim ID, and hashes on their own line are not picked up.
- `identify` is now distinct from `scan`: it takes a single file only and skips the directory walk and entropy.
- STOP/Djvu `t1` no longer upgrades the verdict to "free decryptor available".

### Packaging and project
- Modern `pyproject.toml` (setuptools, console script `ransomtriage`, Python 3.9+, no runtime dependencies) replaces `setup.py`.
- Added MIT `LICENSE`, `CITATION.cff`, `.gitignore`, GitHub Actions CI (3.9 to 3.12), and issue templates.
- Rebuilt the KAPE target/module in valid KAPE syntax. The Velociraptor artifact now fetches the release zipapp as a tool.
- README: Beta status, sample output, families table, limitations, disclaimer, and CISA / NIST IR 8374 Rev. 1 mapping.

## [0.2.0]
- Internal pre-release (not published).
