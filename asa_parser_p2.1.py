# ============================================================
# ASA Migration Parser - Phase 2: Section Extraction and
#                                  Content Validation
# ============================================================
# PURPOSE:
#   Reads a structured ASA log file and validates that all
#   expected section headers are present and contain content.
#   Run this before Phase 3 to confirm your log file is
#   correctly structured before running the full parser chain.
#
# USAGE:
#   python asa_parser_p2.py <path_to_log_file>
#   Example: python asa_parser_p2.py asa_logs.txt
#
# OUTPUT:
#   Per-section status report:
#     - Start line number in the log file
#     - Line count
#     - Content status: [OK] or [EMPTY]
#     - Preview of first 3 non-blank lines
#   Summary of empty sections and missing expected sections.
#
# SECTION HEADER FORMAT (required in log file):
#   ! ===SECTION: <SECTION-NAME>===
#   Section names are case-insensitive. Names are normalized
#   to uppercase internally.
#
# SHOW COMMAND → SECTION HEADER MAPPING:
#   show running-config all          → RUNNING-CONFIG-ALL
#   show running-config              → RUNNING-CONFIG
#   show interface                   → INTERFACE
#   show interface ip brief          → INTERFACE-IP-BRIEF
#   show access-list                 → ACCESS-LIST
#   show access-list element-count   → ACCESS-LIST-ELEMENTS
#   show running-config access-list  → RUNNING-CONFIG-ACCESS-LIST
#   show route                       → ROUTE
#   show running-config route        → RUNNING-CONFIG-ROUTE
#   show running-config crypto       → RUNNING-CONFIG-CRYPTO
#   show vpn-sessiondb summary       → VPN-SESSIONDB-SUMMARY
#   show vpn-sessiondb anyconnect    → VPN-SESSIONDB-ANYCONNECT
#   show vpn-sessiondb l2l           → VPN-SESSIONDB-L2L
#   show vpn-sessiondb ratio enc...  → VPN-SESSIONDB-RATIO-ENC
#   show vpn-sessiondb ratio proto.. → VPN-SESSIONDB-RATIO-PROTO
#   show vpn-sessiondb detail        → VPN-SESSIONDB-DETAIL
#   show vpn-sessiondb full          → VPN-SESSIONDB-FULL
#   show crypto isakmp sa            → CRYPTO-ISAKMP-SA
#   show crypto ikev1 sa             → CRYPTO-IKEv1-SA
#   show crypto ikev2 sa             → CRYPTO-IKEv2-SA
#   show crypto ipsec sa             → CRYPTO-IPSEC-SA
#   show crypto ipsec policy stats   → CRYPTO-IPSEC-STATS
#   show crypto isakmp stats         → CRYPTO-ISAKMP-STATS
#   show service-policy              → SERVICE-POLICY
#   show running-config log          → RUNNING-CONFIG-LOG
#   show logging                     → LOGGING
#   show running-config aaa          → RUNNING-CONFIG-AAA
#   show running-config aaa-server   → RUNNING-CONFIG-AAA-SERVER
# ============================================================

import re
import sys
import os


# ════════════════════════════════════════════════════════════
# EXPECTED SECTIONS
# Matches the show commands collected from the ASA.
# Update this list if the show command set changes.
# ════════════════════════════════════════════════════════════

EXPECTED_SECTIONS = [
    # ── Running configuration ─────────────────────────────────
    "RUNNING-CONFIG-ALL",
    "RUNNING-CONFIG",
    # ── Interfaces ───────────────────────────────────────────
    "INTERFACE",
    "INTERFACE-IP-BRIEF",
    # ── Access lists ─────────────────────────────────────────
    "ACCESS-LIST",
    "ACCESS-LIST-ELEMENTS",
    "RUNNING-CONFIG-ACCESS-LIST",
    # ── Routing ──────────────────────────────────────────────
    "ROUTE",
    "RUNNING-CONFIG-ROUTE",
    # ── Crypto configuration ──────────────────────────────────
    "RUNNING-CONFIG-CRYPTO",
    # ── VPN session database ──────────────────────────────────
    "VPN-SESSIONDB-SUMMARY",
    "VPN-SESSIONDB-ANYCONNECT",
    "VPN-SESSIONDB-L2L",
    "VPN-SESSIONDB-RATIO-ENC",
    "VPN-SESSIONDB-RATIO-PROTO",
    "VPN-SESSIONDB-DETAIL",
    "VPN-SESSIONDB-FULL",
    # ── Active crypto SAs ─────────────────────────────────────
    "CRYPTO-ISAKMP-SA",
    "CRYPTO-IKEv1-SA",
    "CRYPTO-IKEv2-SA",
    "CRYPTO-IPSEC-SA",
    "CRYPTO-IPSEC-STATS",
    "CRYPTO-ISAKMP-STATS",
    # ── Service policy ────────────────────────────────────────
    "SERVICE-POLICY",
    # ── Logging ──────────────────────────────────────────────
    "RUNNING-CONFIG-LOG",
    "LOGGING",
    # ── AAA ──────────────────────────────────────────────────
    "RUNNING-CONFIG-AAA",
    "RUNNING-CONFIG-AAA-SERVER",
]


# ════════════════════════════════════════════════════════════
# SECTION HEADER PATTERN
# ════════════════════════════════════════════════════════════

SECTION_PATTERN = re.compile(
    r'^!\s*===SECTION:\s*([A-Z0-9_\-]+)\s*===$',
    re.IGNORECASE
)


# ════════════════════════════════════════════════════════════
# SECTION EXTRACTION
# ════════════════════════════════════════════════════════════

def extract_sections(filepath):
    """
    Reads the entire log file and extracts content per section.

    Returns a tuple:
      sections_data : dict  { section_name: [lines] }
      sections_meta : list  [ (section_name, start_line_number) ]
      total_lines   : int
    """
    sections_data = {}
    sections_meta = []
    current_section = None
    total_lines = 0

    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line_num, line in enumerate(f, start=1):
            total_lines = line_num
            stripped = line.strip()

            match = SECTION_PATTERN.match(stripped)
            if match:
                current_section = match.group(1).upper().strip()
                sections_data[current_section] = []
                sections_meta.append((current_section, line_num))
            elif current_section is not None:
                sections_data[current_section].append(stripped)

    return sections_data, sections_meta, total_lines


def has_content(lines):
    """Returns True if a section has at least one non-blank line."""
    return any(line.strip() for line in lines)


# ════════════════════════════════════════════════════════════
# EXTRACTION REPORT
# ════════════════════════════════════════════════════════════

def print_extraction_report(sections_data, sections_meta,
                            total_lines, filepath):
    """
    Prints a detailed extraction report showing per-section
    status, content preview, empty section warnings, and
    missing expected section warnings.
    """
    print("=" * 65)
    print("  ASA LOG FILE — SECTION EXTRACTION REPORT")
    print("=" * 65)
    print(f"  File          : {filepath}")
    print(f"  Total lines   : {total_lines}")
    print(f"  Sections found: {len(sections_data)}")
    print("=" * 65)

    empty_sections = []

    for idx, (name, start_line) in enumerate(sections_meta):
        lines = sections_data.get(name, [])
        line_count = len(lines)
        content_present = has_content(lines)

        if not content_present:
            empty_sections.append(name)
            status = "[EMPTY]"
        else:
            status = "[OK]"

        print(f"\n  [{idx+1:02d}] {name}")
        print(f"        Start line : {start_line}")
        print(f"        Line count : {line_count}")
        print(f"        Status     : {status}")

        if content_present:
            preview_lines = [l for l in lines if l.strip()][:3]
            print(f"        Preview    :")
            for pl in preview_lines:
                display = pl if len(pl) <= 80 else pl[:77] + "..."
                print(f"          {display}")

    # ── Empty section summary ─────────────────────────────────
    print("\n" + "=" * 65)
    print("  EMPTY SECTION SUMMARY")
    print("=" * 65)

    if not empty_sections:
        print("  [OK] All sections contain content.")
    else:
        print(f"  [WARNING] {len(empty_sections)} section(s) have no content:")
        for s in empty_sections:
            print(f"    - {s}")
        print()
        print("  This is expected if a command produced no output on this")
        print("  device. Populate and re-run to confirm after collecting")
        print("  updated show command output.")

    # ── Missing expected sections ─────────────────────────────
    found_names = set(sections_data.keys())
    missing = [s for s in EXPECTED_SECTIONS if s not in found_names]

    print("\n" + "=" * 65)
    print("  EXPECTED SECTION VALIDATION")
    print("=" * 65)

    if not missing:
        print("  [OK] All expected sections present.")
    else:
        print(f"  [WARNING] {len(missing)} expected section(s) missing:")
        for m in missing:
            print(f"    - {m}")
        print()
        print("  Add the missing section header(s) to your log file")
        print("  and paste the corresponding show command output.")
        print()
        print("  Section header format:")
        print("    ! ===SECTION: <SECTION-NAME>===")

    # ── Unexpected sections ───────────────────────────────────
    unexpected = sorted(found_names - set(EXPECTED_SECTIONS))
    if unexpected:
        print("\n" + "=" * 65)
        print("  UNEXPECTED SECTIONS (not in expected list)")
        print("=" * 65)
        print("  These sections were found but are not in EXPECTED_SECTIONS.")
        print("  They will still be parsed if a parser exists for them.")
        for u in unexpected:
            print(f"    - {u}")

    print("=" * 65)
    print()


# ════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════

def main():
    if len(sys.argv) != 2:
        print("Usage: python asa_parser_p2.py <path_to_log_file>")
        print("Example: python asa_parser_p2.py asa_logs.txt")
        sys.exit(1)

    filepath = sys.argv[1]

    if not os.path.isfile(filepath):
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)

    if os.path.getsize(filepath) == 0:
        print(f"[ERROR] File is empty: {filepath}")
        sys.exit(1)

    print(f"\n  Reading: {filepath}\n")

    sections_data, sections_meta, total_lines = extract_sections(filepath)
    print_extraction_report(
        sections_data, sections_meta, total_lines, filepath
    )


if __name__ == "__main__":
    main()
