# ============================================================
# ASA Migration Parser - Phase 2: Section Extraction
# ============================================================
# PURPOSE:
#   Builds on Phase 1. Reads the structured ASA log file,
#   detects all section headers, and extracts the raw text
#   content beneath each header into a dictionary.
#
#   Result: a dictionary where:
#     key   = section name (e.g. "RUNNING-CONFIG-CRYPTO")
#     value = list of lines belonging to that section
#
# USAGE:
#   python asa_parser_p2.py <path_to_log_file>
#   Example: python asa_parser_p2.py asa_logs.txt
#
# OUTPUT:
#   - Table of contents with section name, start line, line count
#   - Preview of first 3 lines of content per section
#   - Summary of empty sections (headers with no content below)
#
# ASSUMPTIONS:
#   - Section headers match exactly: ! ===SECTION: <NAME>===
#   - Content belonging to a section ends when the next
#     section header is encountered, or at end of file
#   - Blank lines between header and content are preserved
#     but not counted toward "has content" check
#   - File is plain text, UTF-8 or ASCII encoded
# ============================================================

import re
import sys
import os

# ── Expected sections ────────────────────────────────────────
EXPECTED_SECTIONS = [
    "RUNNING-CONFIG-ALL",
    "RUNNING-CONFIG",
    "INTERFACE",
    "INTERFACE-IP-BRIEF",
    "ACCESS-LIST",
    "ACCESS-LIST-ELEMENTS",
    "RUNNING-CONFIG-ACCESS-LIST",
    "ROUTE",
    "RUNNING-CONFIG-ROUTE",
    "RUNNING-CONFIG-CRYPTO",
    "RUNNING-CONFIG-IP-POOL",
    "VPN-SESSIONDB-SUMMARY",
    "VPN-SESSIONDB-ANYCONNECT",
    "CRYPTO-ISAKMP-SA",
    "CRYPTO-IPSEC-SA",
    "SERVICE-POLICY",
    "RUNNING-CONFIG-LOGGING",
    "LOGGING",
    "RUNNING-CONFIG-AAA",
    "RUNNING-CONFIG-AAA-SERVER",
]

# ── Regex pattern ────────────────────────────────────────────
SECTION_PATTERN = re.compile(
    r'^!\s*===SECTION:\s*([A-Z0-9_\-]+)\s*===$',
    re.IGNORECASE
)


def extract_sections(filepath):
    """
    Reads the entire log file and extracts content per section.

    Returns a tuple:
      - sections_data : dict  { section_name: [lines] }
      - sections_meta : list  [ (section_name, start_line) ]
      - total_lines   : int
    """
    sections_data = {}   # { name: [content lines] }
    sections_meta = []   # [ (name, start_line_number) ]

    current_section = None
    total_lines = 0

    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line_num, line in enumerate(f, start=1):
            total_lines = line_num
            stripped = line.strip()

            match = SECTION_PATTERN.match(stripped)
            if match:
                # New section header detected
                current_section = match.group(1).upper().strip()
                sections_data[current_section] = []
                sections_meta.append((current_section, line_num))
            elif current_section is not None:
                # We are inside a section — append line to its content
                # Store stripped line; preserves structure, drops \n
                sections_data[current_section].append(stripped)

    return sections_data, sections_meta, total_lines


def has_content(lines):
    """
    Returns True if a section has at least one non-blank line.
    Used to detect sections that exist but have no log output yet.
    """
    return any(line.strip() for line in lines)


def print_extraction_report(sections_data, sections_meta, total_lines, filepath):
    """
    Prints a detailed extraction report:
    - File summary
    - Per-section: start line, line count, content status, preview
    - Empty section warnings
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

        # Preview first 3 non-blank lines of content
        if content_present:
            preview_lines = [l for l in lines if l.strip()][:3]
            print(f"        Preview    :")
            for pl in preview_lines:
                # Truncate long lines for display only
                display = pl if len(pl) <= 80 else pl[:77] + "..."
                print(f"          {display}")

    # ── Empty section summary ────────────────────────────────
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
        print("  This is expected if you have not yet pasted log output")
        print("  under those headers. Populate and re-run to confirm.")

    # ── Missing expected sections ────────────────────────────
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

    print("=" * 65)
    print()


def main():
    # ── Argument handling ────────────────────────────────────
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
    print_extraction_report(sections_data, sections_meta, total_lines, filepath)


if __name__ == "__main__":
    main()
