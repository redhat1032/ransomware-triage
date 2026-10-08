# ransomtriage: offline first-hour ransomware triage

[![CI](https://github.com/redhat1032/ransomware-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/redhat1032/ransomware-triage/actions/workflows/ci.yml)
![Status: Beta](https://img.shields.io/badge/status-beta-yellow)
![Python 3.9-3.12](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue)
![Dependencies: none](https://img.shields.io/badge/runtime%20dependencies-none-success)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Offline, privacy-preserving first-hour ransomware triage. Nothing is uploaded.**

`ransomtriage` reads ransom notes and encrypted files on the affected machine (or a copy). It then:

- suggests the likely ransomware family,
- tells you whether a free decryptor is known (with its limits and sources),
- extracts the attacker's indicators (wallets, Tor sites, contacts, victim IDs), and
- gives you a first-hour checklist mapped to the CISA #StopRansomware Guide and NIST IR 8374 Rev. 1.

It is a single pure-Python file with no dependencies, so it also runs on isolated or air-gapped systems.

> **Status: Beta.** Identification uses heuristics and a small, hand-verified catalog (27 families).
> Treat the output as a lead, not a conclusion. See [Limitations](#limitations).

## Why

Online services such as [ID Ransomware](https://id-ransomware.malwarehunterteam.com/) and
[No More Ransom's Crypto Sheriff](https://www.nomoreransom.org/crypto-sheriff.php) are excellent and cover far more
families, but they need you to upload a note or encrypted files. That isn't always allowed (HIPAA, GDPR,
contracts) or possible (no network after isolation). `ransomtriage` gives you a first answer locally, then points you to
those services and to the official decryptors.

## Quick start

```bash
# Option 1: single-file zipapp from the latest GitHub Release (needs only Python 3.9+)
python3 ransomtriage.pyz scan /path/to/affected/folder

# Option 2: install from source
git clone https://github.com/redhat1032/ransomware-triage.git
cd ransomware-triage
python3 -m pip install .
ransomtriage scan /path/to/affected/folder
```

| Command | What it does |
| --- | --- |
| `ransomtriage scan <dir-or-file>` | Walks a folder (up to 10,000 files): notes, extensions, entropy sampling, original/encrypted file pairs. |
| `ransomtriage identify <file>` | Looks at **one** file (usually the ransom note). No directory walk and no entropy, so it's fast. Rejects directories. |
| `ransomtriage extract <note>` | Prints only the indicators (wallets, Tor, emails, Telegram, Tox, IDs, amounts, deadlines). |
| `ransomtriage list-families [--search X]` | Browses the bundled catalog (`--format json` for machine use). |

Useful options for `scan`/`identify`: `--format text|markdown|json`, `--output report.md`,
`--export-iocs iocs.txt`, `--export-yara rule.yar`. A YARA rule is written only when there is something specific to
match; otherwise the export is skipped with a message.

## Sample output

```text
$ ransomtriage identify examples/stop-djvu/_readme.txt
========================================================================
RANSOMWARE TRIAGE REPORT (ransomtriage)
========================================================================
Target  : examples/stop-djvu/_readme.txt
Verdict : CONDITIONALLY RECOVERABLE (STOP/Djvu): depends on variant, key type or file pairs.
Catalog : last verified 2026-10-08
========================================================================

[+] FAMILY MATCHES
------------------------------------------------------------------------
  #1 STOP/Djvu  [CONFIRMED by note text; confidence high, score 17]
     Status     : CONDITIONALLY RECOVERABLE
     Evidence   : note-filename=_readme.txt, note-keyword=attention! don't worry my friend, ...
     Decryptors (check the limits before use):
       - Emsisoft STOP Djvu Decryptor (Emsisoft)
         https://www.emsisoft.com/en/ransomware-decryption/stop-djvu/
         Decrypts files only if they were encrypted with an OFFLINE key that Emsisoft holds. ...

[+] INDICATORS FROM NOTE TEXT
------------------------------------------------------------------------
  Victim/personal IDs   : 0123SampleOnlineIdForTestingOnly
  Deadlines             : 72 hours

[+] FIRST-HOUR CHECKLIST (CISA #StopRansomware Guide / NIST IR 8374 Rev. 1)
------------------------------------------------------------------------
  1. Isolate affected systems: unplug network cables / disable Wi-Fi; ...
     [CISA Steps 1-2 | NIST CSF RS.MI-01]
  ...
```

## How identification works (and why it's conservative)

- **Note text decides.** A family is **confirmed** only when ransom-note text matches: either a distinctive phrase, or the
  family's own name inside a file that reads like a ransom note. File names and extensions alone only give an
  **UNCONFIRMED** candidate and no verdict, because extensions are reused, randomised and spoofed.
- **Whole words only.** Matching uses word boundaries. Generic markers such as `play`, `tor`, `onion` or a bare
  `readme.txt` file name are never used as evidence.
- **Checked wallets.** Bitcoin addresses are kept only if their checksum is valid (Base58Check, Bech32/Bech32m).
  Monero addresses are matched by format only.
- **Bounded reads.** At most 512 KB of any file is read for text analysis, so huge files can't exhaust memory.

## Supported families

Every catalog entry has source URLs and a `last_verified` date in
[`ransomtriage/signatures.json`](ransomtriage/signatures.json). Decryptor coverage changes, so always re-check
[No More Ransom](https://www.nomoreransom.org/en/decryption-tools.html).

| Family | Status | Free decryptor(s) |
| --- | --- | --- |
| STOP/Djvu | Conditional | [Emsisoft STOP Djvu Decryptor](https://www.emsisoft.com/en/ransomware-decryption/stop-djvu/) |
| LockBit | Some keys recovered | [LockBit 3.0 Decryption ID Checker](https://www.nomoreransom.org/en/decryption-tools.html#Lockbit30) |
| Akira | Conditional | [Avast Akira Decryptor](https://www.nomoreransom.org/en/decryption-tools.html#Akira) |
| BlackCat / ALPHV | None known | None known |
| Black Basta | Conditional | [Black Basta Buster](https://github.com/srlabs/black-basta-buster) |
| Phobos / 8Base | Free decryptor listed | [Phobos/8Base Decryptor (PhDec)](https://www.npa.go.jp/english/bureau/cyber/ransomdamagerecovery.html) |
| Dharma / CrySIS | Free decryptor listed | [Kaspersky Rakhni Decryptor](https://www.nomoreransom.org/en/decryption-tools.html#Dharma) |
| Play | None known | None known |
| Babuk | Free decryptor listed | [Avast Babuk Decryptor](https://www.nomoreransom.org/en/decryption-tools.html#Babuk) |
| Hive | Free decryptor listed | [KISA Hive (v1 to v4) Decryptor](https://www.nomoreransom.org/en/decryption-tools.html#Hivev1tov4) |
| Hunters International | None known | None known |
| Rhysida | Free decryptor listed | [Avast Rhysida Decryptor](https://www.nomoreransom.org/en/decryption-tools.html#Rhysida), [KISA Rhysida Recovery Tool](https://seed.kisa.or.kr/kisa/Board/166/detailView.do) |
| BianLian | Conditional | [Avast BianLian Decryptor](https://www.nomoreransom.org/en/decryption-tools.html#Bianlian) |
| Mallox / TargetCompany | Conditional | [Avast Mallox Decryptor](https://www.gendigital.com/blog/insights/research/decrypted-mallox-ransomware), [Avast TargetCompany Decryptor](https://www.nomoreransom.org/en/decryption-tools.html#TargetCompany) |
| Makop | None known | None known |
| DeadBolt | Some keys recovered | [DeadBolt key lookup (Responders.NU / Dutch Police)](https://www.bleepingcomputer.com/news/security/police-tricks-deadbolt-ransomware-out-of-155-decryption-keys/) |
| WannaCry | Conditional | [wanakiwi (memory key recovery)](https://github.com/gentilkiwi/wanakiwi) |
| GandCrab | Free decryptor listed | [Bitdefender GandCrab Decryption Tool](https://www.nomoreransom.org/en/decryption-tools.html#GandCrabV1V4andV5uptoV52versions) |
| REvil / Sodinokibi | Free decryptor listed | [Bitdefender REvil/Sodinokibi Universal Decryptor](https://www.nomoreransom.org/en/decryption-tools.html#REvilSodinokibi) |
| Avaddon | Free decryptor listed | [Avaddon Decryptors (Bitdefender, Emsisoft)](https://www.nomoreransom.org/en/decryption-tools.html#Avaddon) |
| Royal / BlackSuit | None known | None known |
| Medusa | None known | None known |
| Qilin | None known | None known |
| RansomHub | None known | None known |
| Cactus | None known | None known |
| Clop | None known | None known |
| Destructive wiper (fake ransomware) | Wiper (no key) | None known |

"Conditional" means a decryptor exists but only for some variants, key types or situations. Read the notes in the
report before relying on it.

## First-hour checklist: CISA and NIST mapping

The checklist printed in every report follows Part 2 of the
[CISA #StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide) ("Ransomware and Data Extortion
Response Checklist") and the Respond/Recover outcomes in
[NIST IR 8374 Rev. 1](https://csrc.nist.gov/pubs/ir/8374/r1/final) (*Ransomware Risk Management: A Cybersecurity
Framework 2.0 Community Profile*, June 2026).

| # | Action | CISA guide, Part 2 | NIST CSF 2.0 outcome |
| --- | --- | --- | --- |
| 1 | Isolate affected systems; power down only if you can't disconnect | Steps 1-2 | RS.MI-01 |
| 2 | Don't wipe or reinstall; capture memory and disk images where possible | Step 9 | DE.AE-02 |
| 3 | Preserve notes, encrypted samples and logs; don't rename files | Reporting list; Step 9 | DE.AE-02, RS.CO-03 |
| 4 | Check for free decryptors and ask law enforcement; test on copies | Steps 10-11 | RC.RP-02 |
| 5 | Report and notify (CISA, FBI IC3, national CERT, insurer, counsel) | Steps 7-8 | RS.MA-01, RS.CO-02, RS.CO-03 |
| 6 | Hunt for initial access, persistence and exfiltration | Steps 4, 6, 12-15 | DE.AE-04, RS.MI-02 |
| 7 | Restore from verified offline backups after cleanup; reset credentials | Steps 16-17, 19 | RC.RP-01, RC.RP-03 |
| 8 | Avoid "guaranteed recovery" brokers; paying isn't recommended | Part 2 introduction | DE.AE-04 |
| 9 | Document lessons learned; share indicators | Steps 20-21 | RS.CO-03, RC.CO-03 |

This is a convenience mapping for triage, not a compliance assessment.

## Integrations

- **Velociraptor:** [`integrations/velociraptor/Windows.Detection.RansomwareTriage.yaml`](integrations/velociraptor/Windows.Detection.RansomwareTriage.yaml)
  fetches the release zipapp as a tool and returns the JSON report. Needs Python 3.9+ on the endpoint.
- **KAPE:** [`integrations/kape/`](integrations/kape/) has a target that collects likely ransom notes and a module that
  runs the zipapp over them.

Both integrations are syntax-checked but **not yet tested against live Velociraptor/KAPE deployments**. Please
open an issue if you try them.

## Limitations

- The catalog is small (27 families) and hand-maintained. Many families, especially new ones, will come back as
  UNKNOWN or UNCONFIRMED. Use ID Ransomware / Crypto Sheriff when you can share samples.
- Families with random extensions and generic note names (e.g. Play's `ReadMe.txt`) can only be confirmed from
  note text, and some notes contain no distinctive text.
- Heuristics can be fooled: a document that talks *about* ransomware can look like a note.
- Entropy and file-pair hints are rough signals, not cryptanalysis.
- The tool does not decrypt anything, remove malware, or check whether attackers are still in your network.
- Decryptor information was verified on the `last_verified` date and can go out of date.

## Disclaimer

This software is provided "as is", without warranty of any kind (see [LICENSE](LICENSE)). It gives triage hints, **not
guarantees**: identification can be wrong and decryptors may not work for your case.

- Always check [No More Ransom](https://www.nomoreransom.org/) and get professional incident-response help.
- Report to law enforcement ([CISA](https://www.cisa.gov/report) / [FBI IC3](https://www.ic3.gov/) in the US, or your
  national authority).
- **Never pay "recovery" brokers** who promise guaranteed decryption. Some simply pay the criminals and add a fee.
- Work on copies. Don't run decryptors on your only copy of the data.

## Development

```bash
python3 -m unittest discover -s tests        # tests (stdlib only)
python3 -m pip install ruff build twine       # optional dev tools
ruff check .
python3 tools/build_standalone.py             # builds dist/ransomtriage.pyz
python3 -m build && twine check dist/*        # sdist + wheel
python3 tools/build_catalog.py                # regenerate signatures.json from sourced data
python3 tools/verify_urls.py                  # check every catalog URL still resolves
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the catalog rules. To report a security problem, see [SECURITY.md](SECURITY.md).

## License and citation

MIT, Copyright (c) 2026 Douglas Weant. If you use this in research, see [CITATION.cff](CITATION.cff).
