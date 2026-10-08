"""Render a TriageReport as text, Markdown, JSON or a plain IOC list."""

from __future__ import annotations

import json
from dataclasses import asdict

from .engine import FamilyMatch, TriageReport

DISCLAIMER = (
    "ransomtriage gives triage hints, not guarantees. Identification can be wrong and decryptor coverage "
    "changes. Always check No More Ransom, get professional incident-response help, and never pay "
    "'recovery' brokers who promise guaranteed decryption."
)


def _evidence_text(match: FamilyMatch, limit: int = 6) -> str:
    parts = []
    for item in match.evidence[:limit]:
        suffix = f" (x{item.count})" if item.count > 1 else ""
        parts.append(f"{item.kind}={item.value}{suffix}")
    return ", ".join(parts)


def format_text(report: TriageReport) -> str:
    border, sub = "=" * 72, "-" * 72
    out: list[str] = [
        border,
        "RANSOMWARE TRIAGE REPORT (ransomtriage)",
        border,
        f"Target  : {report.target}",
        f"Verdict : {report.summary_verdict}",
        f"Catalog : last verified {report.catalog_updated or 'unknown'}",
        border,
        "",
        "[+] FAMILY MATCHES",
        sub,
    ]
    if not report.matches:
        out.append("  No match in the local catalog.")
        out.append("  Try No More Ransom Crypto Sheriff or ID Ransomware (both need an upload).")
    for idx, match in enumerate(report.matches[:3], 1):
        state = "CONFIRMED by note text" if match.confirmed else "UNCONFIRMED (file indicators only)"
        out.append(f"  #{idx} {match.family}  [{state}; confidence {match.confidence}, score {match.score}]")
        if match.confirmed:
            out.append(f"     Status     : {match.verdict}")
        out.append(f"     Evidence   : {_evidence_text(match)}")
        out.append(f"     Data theft : {match.exfiltration_risk}")
        out.append(f"     Summary    : {match.summary}")
        if match.note:
            out.append(f"     Note       : {match.note}")
        out.append(f"     Preserve   : {match.preserve_advice}")
        if match.decryptors:
            out.append("     Decryptors (check the limits before use):")
            for dec in match.decryptors:
                out.append(f"       - {dec.name} ({dec.provider})")
                out.append(f"         {dec.url}")
                out.append(f"         {dec.notes}")
        else:
            out.append("     Decryptors : no free decryptor known as of the catalog date. Re-check No More Ransom.")
        if match.sources:
            more = f" (+{len(match.sources) - 1} more)" if len(match.sources) > 1 else ""
            out.append(f"     Sources    : {match.sources[0]}{more}")
        out.append("")
    out.append("")

    out += ["[+] INDICATORS FROM NOTE TEXT", sub]
    iocs = report.iocs
    if iocs.is_empty():
        out.append("  None found.")
    rows = [
        ("Victim/personal IDs", iocs.victim_ids),
        ("Bitcoin (checksum OK)", iocs.bitcoin_addresses),
        ("Monero", iocs.monero_addresses),
        ("Ethereum", iocs.ethereum_addresses),
        ("Tor (.onion)", iocs.onion_urls),
        ("Emails", iocs.emails),
        ("Telegram", iocs.telegram_handles),
        ("Tox IDs", iocs.tox_ids),
        ("Amounts", iocs.ransom_amounts),
        ("Deadlines", iocs.deadlines),
    ]
    for label, values in rows:
        if values:
            out.append(f"  {label:<22}: {', '.join(values)}")
    out.append("")

    if report.file_pairs or report.entropy_profiles:
        out += ["[+] FILE OBSERVATIONS", sub]
        for pair in report.file_pairs:
            out.append(f"  Original/encrypted pair: {pair.original_path} <-> {pair.encrypted_path}")
        for profile in report.entropy_profiles[:6]:
            flag = " [INTERMITTENT]" if profile.is_intermittent else ""
            out.append(f"  {profile.path}: entropy {profile.overall_entropy}/8 ({profile.classification}){flag}")
        out.append("")

    out += ["[+] WARNINGS", sub]
    out += [f"  [!] {w}" for w in report.warnings] or ["  None."]
    out.append("")

    out += ["[+] FIRST-HOUR CHECKLIST (CISA #StopRansomware Guide / NIST IR 8374 Rev. 1)", sub]
    for number, item in enumerate(report.checklist, 1):
        out.append(f"  {number}. {item.step}")
        out.append(f"     [CISA {item.cisa} | NIST CSF {item.nist}]")
    out.append("")

    out += ["[+] WHERE TO GET HELP", sub]
    for res in report.general_resources[:6]:
        out.append(f"  * {res.name} ({res.provider}): {res.url}")
    out += ["", DISCLAIMER, border]
    return "\n".join(out) + "\n"


def format_markdown(report: TriageReport) -> str:
    out: list[str] = [
        "# Ransomware Triage Report",
        "",
        f"- **Target:** `{report.target}`",
        f"- **Verdict:** {report.summary_verdict}",
        f"- **Catalog last verified:** {report.catalog_updated or 'unknown'}",
        "",
        "## Family matches",
        "",
    ]
    if not report.matches:
        out += ["No match in the local catalog. Try No More Ransom Crypto Sheriff or ID Ransomware.", ""]
    for match in report.matches:
        state = "confirmed by note text" if match.confirmed else "UNCONFIRMED: file indicators only"
        out.append(f"### {match.family} ({state})")
        out.append("")
        if match.confirmed:
            out.append(f"- **Status:** {match.verdict}")
        out.append(f"- **Confidence:** {match.confidence} (score {match.score})")
        out.append(f"- **Evidence:** {_evidence_text(match, 20)}")
        out.append(f"- **Data theft:** {match.exfiltration_risk}")
        out.append(f"- **Summary:** {match.summary}")
        if match.note:
            out.append(f"- **Note:** {match.note}")
        out.append(f"- **Preserve:** {match.preserve_advice}")
        if match.decryptors:
            out.append("- **Decryptors:**")
            for dec in match.decryptors:
                out.append(f"  - [{dec.name}]({dec.url}) ({dec.provider}): {dec.notes}")
        else:
            out.append("- **Decryptors:** none known as of the catalog date.")
        if match.sources:
            out.append("- **Sources:** " + ", ".join(f"<{s}>" for s in match.sources))
        out.append("")

    iocs = report.iocs
    out += ["## Indicators from note text", ""]
    if iocs.is_empty():
        out += ["None found.", ""]
    else:
        out += ["| Type | Value |", "| --- | --- |"]
        for label, values in (
            ("Victim ID", iocs.victim_ids),
            ("Bitcoin", iocs.bitcoin_addresses),
            ("Monero", iocs.monero_addresses),
            ("Ethereum", iocs.ethereum_addresses),
            ("Onion", iocs.onion_urls),
            ("Email", iocs.emails),
            ("Telegram", iocs.telegram_handles),
            ("Tox", iocs.tox_ids),
            ("Amount", iocs.ransom_amounts),
            ("Deadline", iocs.deadlines),
        ):
            out += [f"| {label} | `{value}` |" for value in values]
        out.append("")

    if report.file_pairs or report.entropy_profiles:
        out += ["## File observations", ""]
        for pair in report.file_pairs:
            out.append(f"- Pair: `{pair.original_path}` / `{pair.encrypted_path}`")
        for profile in report.entropy_profiles[:10]:
            out.append(f"- `{profile.path}`: entropy {profile.overall_entropy} ({profile.classification})")
        out.append("")

    out += ["## Warnings", ""]
    out += [f"- {w}" for w in report.warnings] or ["- None."]
    out += ["", "## First-hour checklist", ""]
    out += ["| # | Action | CISA guide | NIST CSF 2.0 |", "| --- | --- | --- | --- |"]
    for number, item in enumerate(report.checklist, 1):
        out.append(f"| {number} | {item.step} | {item.cisa} | {item.nist} |")
    out += ["", "## Where to get help", ""]
    out += [f"- [{r.name}]({r.url}) ({r.provider}): {r.notes}" for r in report.general_resources]
    out += ["", f"> {DISCLAIMER}", ""]
    return "\n".join(out)


def format_json(report: TriageReport) -> str:
    data = asdict(report)
    data["confirmed_families"] = [m.family for m in report.confirmed_matches]
    for raw, match in zip(data["matches"], report.matches):
        raw["confirmed"] = match.confirmed
        raw["confidence"] = match.confidence
        raw["verdict"] = match.verdict if match.confirmed else "UNCONFIRMED"
    data["disclaimer"] = DISCLAIMER
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def format_iocs_text(report: TriageReport) -> str:
    """Plain IOC list for blocklists / threat-intel platforms."""
    lines = [f"# ransomtriage IOC export: {report.target}"]
    iocs = report.iocs
    for title, values in (
        ("Tor onion addresses", iocs.onion_urls),
        ("Bitcoin addresses", iocs.bitcoin_addresses),
        ("Monero addresses", iocs.monero_addresses),
        ("Ethereum addresses", iocs.ethereum_addresses),
        ("Email addresses", iocs.emails),
        ("Tox IDs", iocs.tox_ids),
        ("Telegram handles", iocs.telegram_handles),
    ):
        if values:
            lines.append(f"\n# {title}")
            lines.extend(values)
    return "\n".join(lines) + "\n"
