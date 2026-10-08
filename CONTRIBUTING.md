# Contributing to ransomtriage

Contributions from incident responders, malware analysts and threat-intel researchers are welcome.

## Adding or updating a family or decryptor

The catalog is generated: edit [`tools/build_catalog.py`](tools/build_catalog.py), then run

```bash
python3 tools/build_catalog.py    # rewrites ransomtriage/signatures.json
python3 tools/verify_urls.py      # every URL must resolve
python3 -m unittest discover -s tests
```

### Family fields

| Field | Meaning |
| --- | --- |
| `family`, `aliases` | Display name and other names. |
| `decryptability_status` | `AVAILABLE`, `PARTIAL_OR_OFFLINE_ONLY`, `LEAKED_KEY_SET`, `NONE_KNOWN` or `WIPER`. |
| `exfiltration_risk` | `high` only if a source documents data theft; otherwise `unknown`. |
| `note_filenames` | Lower-case note names; `*` wildcards allowed (e.g. `readme-recover-*.txt`). Never generic names like `readme.txt`. |
| `note_keywords` | Distinctive phrases quoted from real notes (whole-phrase match). A match confirms the family. |
| `self_names` | The family's own name as it appears in notes. Counts only inside note-like text. |
| `extensions`, `weak_extensions`, `extension_patterns` | Encrypted-file suffixes. Use `weak_extensions` for generic ones such as `.locked`. |
| `decryptors` | IDs from the `DECRYPTORS` list. Empty for `NONE_KNOWN`, and the summary must say "No free decryptor known". |
| `summary`, `preserve_advice` | Short, factual, no guarantees. |
| `sources` | Public sources for every indicator and claim (CISA/FBI advisories, vendor research, No More Ransom). |

### Rules

1. **Every fact needs a public source.** Indicators must appear in the cited source.
2. **Decryptors must come from a recognised organisation**: No More Ransom partners, law enforcement, national CERTs,
   established security vendors, or published researchers. Never link to forums, Telegram, unverified binaries or
   paid "recovery services".
3. **State the limits.** If a decryptor only covers some versions, dates or key types, say so in `notes`.
4. **No generic markers.** Words like `play`, `tor`, `onion`, `encrypted` or `bitcoin` cause false positives.

## Development

```bash
python3 -m unittest discover -s tests
python3 -m pip install ruff && ruff check .
python3 tools/build_standalone.py
```

Please include a test with every bug fix. Don't commit real victim data. Sanitise any sample notes and use
documentation-style placeholder values.
