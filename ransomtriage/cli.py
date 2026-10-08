"""Command-line interface for ransomtriage."""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path

from . import __version__
from .catalog import load_catalog
from .engine import read_text_excerpt, scan_path
from .extractor import extract_iocs
from .formatters import format_iocs_text, format_json, format_markdown, format_text
from .yara_export import generate_yara_rule

COMMANDS = {"scan", "identify", "extract", "list-families"}


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    argv = list(sys.argv[1:] if argv is None else argv)
    # Backwards compatible shorthand: `ransomtriage <path>` == `ransomtriage scan <path>`.
    if argv and argv[0] not in COMMANDS and not argv[0].startswith("-"):
        argv.insert(0, "scan")
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0
    if args.command == "list-families":
        return _handle_list_families(args)
    if args.command == "extract":
        return _handle_extract(args)
    return _handle_scan(args)


def _handle_scan(args: argparse.Namespace) -> int:
    target = Path(args.target)
    if args.command == "identify" and target.is_dir():
        print(
            "ransomtriage: identify takes a single file (a ransom note or one encrypted file). "
            "Use 'scan' for directories.",
            file=sys.stderr,
        )
        return 2
    check_entropy = args.command == "scan" and not args.no_entropy
    try:
        report = scan_path(target, check_entropy=check_entropy)
    except (OSError, ValueError) as exc:
        print(f"ransomtriage: error: {exc}", file=sys.stderr)
        return 2

    renderers = {"json": format_json, "markdown": format_markdown, "text": format_text}
    rendered = renderers[args.format](report)
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
        print(f"Report written to: {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(rendered)

    if args.export_iocs:
        Path(args.export_iocs).write_text(format_iocs_text(report), encoding="utf-8")
        print(f"IOC list written to: {args.export_iocs}", file=sys.stderr)
    if args.export_yara:
        rule = generate_yara_rule(report)
        if rule is None:
            print("No confirmed family or indicators to build a YARA rule from; YARA export skipped.", file=sys.stderr)
        else:
            Path(args.export_yara).write_text(rule, encoding="utf-8")
            print(f"YARA rule written to: {args.export_yara}", file=sys.stderr)
    return 0


def _handle_list_families(args: argparse.Namespace) -> int:
    catalog = load_catalog()
    query = (args.search or "").lower()
    selected = [
        sig
        for sig in catalog.signatures
        if not query
        or query in sig.family.lower()
        or any(query in alias.lower() for alias in sig.aliases)
        or any(query in ext for ext in sig.extensions)
    ]
    if args.format == "json":
        payload = [dataclasses.asdict(sig) for sig in selected]
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        return 0
    print(
        f"ransomtriage catalog: {len(catalog.signatures)} families (showing {len(selected)}), "
        f"last verified {catalog.updated}"
    )
    print("-" * 72)
    for sig in selected:
        print(f"* {sig.family}  [{sig.decryptability_status}]")
        if sig.aliases:
            print(f"  Aliases    : {', '.join(sig.aliases)}")
        if sig.extensions:
            print(f"  Extensions : {', '.join(sig.extensions)}")
        if sig.note_filenames:
            print(f"  Note names : {', '.join(sig.note_filenames)}")
        names = [catalog.decryptors[d].name for d in sig.decryptors if d in catalog.decryptors]
        print(f"  Decryptor  : {', '.join(names) if names else 'none known'}")
        print(f"  Summary    : {sig.summary}")
        print()
    return 0


def _handle_extract(args: argparse.Namespace) -> int:
    target = Path(args.target)
    if not target.is_file():
        print(f"ransomtriage: not a file: {target}", file=sys.stderr)
        return 2
    iocs = extract_iocs(read_text_excerpt(target) or "")
    if args.format == "json":
        rendered = json.dumps(dataclasses.asdict(iocs), indent=2) + "\n"
    else:
        lines = [f"Indicators in {target.name}:"]
        if iocs.is_empty():
            lines.append("  none found")
        for label, values in (
            ("Victim IDs", iocs.victim_ids),
            ("Bitcoin", iocs.bitcoin_addresses),
            ("Monero", iocs.monero_addresses),
            ("Ethereum", iocs.ethereum_addresses),
            ("Onion", iocs.onion_urls),
            ("Emails", iocs.emails),
            ("Telegram", iocs.telegram_handles),
            ("Tox", iocs.tox_ids),
            ("Amounts", iocs.ransom_amounts),
            ("Deadlines", iocs.deadlines),
        ):
            if values:
                lines.append(f"  {label:<11}: {', '.join(values)}")
        lines += [f"  Note: {note}" for note in iocs.notes]
        rendered = "\n".join(lines) + "\n"
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
        print(f"IOCs written to: {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(rendered)
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ransomtriage",
        description="Offline, privacy-preserving first-hour ransomware triage. Nothing is uploaded.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Triage a directory or file: notes, extensions, entropy, file pairs.")
    _add_report_args(scan)
    scan.add_argument("--no-entropy", action="store_true", help="Skip entropy sampling (faster).")

    identify = sub.add_parser(
        "identify",
        help="Identify the family from ONE file (usually the ransom note). No directory walk, no entropy.",
    )
    _add_report_args(identify)

    extract = sub.add_parser("extract", help="Extract wallets, Tor URLs, contacts and IDs from a note.")
    extract.add_argument("target", help="Ransom note file.")
    extract.add_argument("--format", choices=["text", "json"], default="text")
    extract.add_argument("--output", help="Write to a file instead of stdout.")

    families = sub.add_parser("list-families", help="Browse the bundled family / decryptor catalog.")
    families.add_argument("--search", help="Filter by family, alias or extension.")
    families.add_argument("--format", choices=["text", "json"], default="text")
    return parser


def _add_report_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("target", help="File or directory to inspect.")
    parser.add_argument("--format", choices=["text", "markdown", "json"], default="text")
    parser.add_argument("--output", help="Write the report to a file instead of stdout.")
    parser.add_argument("--export-iocs", help="Also write a plain IOC list to this path.")
    parser.add_argument("--export-yara", help="Also write a YARA rule to this path (skipped if nothing to match).")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
