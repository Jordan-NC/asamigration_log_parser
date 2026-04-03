# ============================================================
# ASA Migration Parser - Phase 3: Basic Section Parsing
# ============================================================
# PURPOSE:
#   Builds on Phase 2. Extracts and structures data from three
#   foundational sections:
#     - INTERFACE-IP-BRIEF  : Interface inventory
#     - ROUTE               : Routing table
#     - VPN-SESSIONDB-SUMMARY: Active VPN session counts
#
# USAGE:
#   python asa_parser_p3.py <path_to_log_file>
#   Example: python asa_parser_p3.py asa_logs.txt
#
# OUTPUT:
#   Structured, human-readable tables for each parsed section.
#   Flags interfaces that are down, default routes, and
#   active VPN session types relevant to migration planning.
#
# ASSUMPTIONS:
#   INTERFACE-IP-BRIEF:
#     Standard ASA output columns:
#     Interface  IP-Address  OK?  Method  Status  Protocol
#     Example:
#     GigabitEthernet0/0  192.168.1.1  YES  CONFIG  up  up
#     Unassigned interfaces show "unassigned" for IP field.
#
#   ROUTE:
#     Standard ASA route table format:
#     <code> <network> <mask> [AD/metric] via <nexthop>, <iface>
#     Codes: C=connected, S=static, O=OSPF, B=BGP, i=IS-IS
#     Example:
#     S    10.0.0.0 255.0.0.0 [1/0] via 192.168.1.1, outside
#     C    192.168.1.0 255.255.255.0 is directly connected, inside
#
#   VPN-SESSIONDB-SUMMARY:
#     ASA summary block format:
#     Session Type: AnyConnect
#     Username : user1  Index : 1  IP Addr : 10.x.x.x
#     ...
#     Session Type: Site-to-Site IKEv1
#     ...
#     Lines with "Active" count:
#     AnyConnect-Parent  : 5    Active : 5
# ============================================================

import re
import sys
import os

# ── Shared constants ─────────────────────────────────────────
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

SECTION_PATTERN = re.compile(
    r'^!\s*===SECTION:\s*([A-Z0-9_\-]+)\s*===$',
    re.IGNORECASE
)

# ── Regex patterns ───────────────────────────────────────────

# INTERFACE-IP-BRIEF
# Matches lines like:
# GigabitEthernet0/0       192.168.1.1     YES CONFIG up                    up
# Management0/0            unassigned      YES unset  up                    up
RE_INTF_BRIEF = re.compile(
    r'^(\S+)\s+'                        # Interface name
    r'([\d\.]+|unassigned)\s+'          # IP address or "unassigned"
    r'(YES|NO)\s+'                      # OK?
    r'(\S+)\s+'                         # Method (CONFIG, DHCP, manual, etc.)
    r'([\w\s]+?)\s{2,}'                 # Status (up, down, admin down)
    r'(up|down)',                       # Protocol
    re.IGNORECASE
)

# ROUTE TABLE
# Matches lines like:
# S    10.0.0.0 255.255.255.0 [1/0] via 192.168.1.1, outside
# C    10.1.1.0 255.255.255.0 is directly connected, inside
# S*   0.0.0.0 0.0.0.0 [1/0] via 10.0.0.1, outside
RE_ROUTE = re.compile(
    r'^([A-Za-z\*\s]{1,5})\s+'         # Route code (C, S, S*, O, B, i, etc.)
    r'([\d\.]+)\s+'                     # Network address
    r'([\d\.]+)\s+'                     # Subnet mask
    r'(?:\[(\d+/\d+)\]\s+)?'           # Optional [AD/metric]
    r'(?:via\s+([\d\.]+),?\s*)?'        # Optional next-hop IP
    r'(?:is directly connected,\s*)?'   # OR directly connected
    r'(\S+)?'                           # Interface name
)

# VPN SESSION SUMMARY
# Matches active session count lines like:
# AnyConnect-Parent        : 12   Active : 12   Cumulative : 45
# Site-to-Site IKEv2       : 3    Active : 3    Cumulative : 8
RE_VPN_SUMMARY = re.compile(
    r'^(.+?)\s*:\s*(\d+)\s+Active\s*:\s*(\d+)',
    re.IGNORECASE
)

# VPN session type header lines
# "Session Type: AnyConnect" etc.
RE_VPN_TYPE = re.compile(
    r'^Session Type:\s*(.+)',
    re.IGNORECASE
)


# ════════════════════════════════════════════════════════════
# SECTION EXTRACTION (reused from Phase 2)
# ════════════════════════════════════════════════════════════

def extract_sections(filepath):
    """
    Reads the log file and returns a dict of section -> [lines].
    Identical to Phase 2 extraction logic.
    """
    sections_data = {}
    current_section = None

    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            stripped = line.strip()
            match = SECTION_PATTERN.match(stripped)
            if match:
                current_section = match.group(1).upper().strip()
                sections_data[current_section] = []
            elif current_section is not None:
                sections_data[current_section].append(stripped)

    return sections_data


# ════════════════════════════════════════════════════════════
# PARSER 1: INTERFACE-IP-BRIEF
# ════════════════════════════════════════════════════════════

def parse_interface_brief(lines):
    """
    Parses 'show interface ip brief' output.

    Returns list of dicts:
    {
        'interface': str,
        'ip'       : str,   # IP or 'unassigned'
        'ok'       : str,   # YES / NO
        'method'   : str,
        'status'   : str,   # up / down / admin down
        'protocol' : str    # up / down
    }
    """
    interfaces = []

    for line in lines:
        # Skip header lines
        if line.lower().startswith('interface') and 'ip-address' in line.lower():
            continue
        if not line.strip():
            continue

        match = RE_INTF_BRIEF.match(line)
        if match:
            interfaces.append({
                'interface': match.group(1),
                'ip'       : match.group(2),
                'ok'       : match.group(3),
                'method'   : match.group(4),
                'status'   : match.group(5).strip(),
                'protocol' : match.group(6),
            })

    return interfaces


def print_interface_brief(interfaces):
    """
    Prints interface brief table with migration-relevant flags.
    """
    print("=" * 75)
    print("  INTERFACE INVENTORY  (show interface ip brief)")
    print("=" * 75)

    if not interfaces:
        print("  [WARNING] No interfaces parsed. Check section content.")
        print("  Expected format: GigabitEthernet0/0  192.168.1.1  YES CONFIG up  up")
        return

    # Column headers
    print(f"  {'INTERFACE':<30} {'IP ADDRESS':<18} {'STATUS':<12} {'PROTOCOL':<10} {'FLAGS'}")
    print(f"  {'-'*29} {'-'*17} {'-'*11} {'-'*9} {'-'*20}")

    down_count = 0
    unassigned_count = 0

    for intf in interfaces:
        flags = []

        # Flag interfaces that are down — relevant for migration planning
        if intf['status'].lower() != 'up':
            flags.append('DOWN')
            down_count += 1

        # Flag unassigned — may indicate unused interfaces
        if intf['ip'].lower() == 'unassigned':
            flags.append('NO IP')
            unassigned_count += 1

        # Flag admin down specifically
        if 'admin' in intf['status'].lower():
            flags.append('ADMIN-DOWN')

        flag_str = ' | '.join(flags) if flags else ''

        print(f"  {intf['interface']:<30} {intf['ip']:<18} "
              f"{intf['status']:<12} {intf['protocol']:<10} {flag_str}")

    # Summary
    print(f"\n  Total interfaces : {len(interfaces)}")
    print(f"  Down/Admin-down  : {down_count}")
    print(f"  No IP assigned   : {unassigned_count}")
    print()
    if down_count > 0:
        print("  [MIGRATION NOTE] Down interfaces — confirm whether these")
        print("  need to be migrated or decommissioned on FTD.")
    print()


# ════════════════════════════════════════════════════════════
# PARSER 2: ROUTE TABLE
# ════════════════════════════════════════════════════════════

# Route code descriptions for human-readable output
ROUTE_CODES = {
    'C' : 'Connected',
    'S' : 'Static',
    'S*': 'Static Default',
    'O' : 'OSPF',
    'O*': 'OSPF Default',
    'B' : 'BGP',
    'i' : 'IS-IS',
    'D' : 'EIGRP',
    'EX': 'EIGRP External',
    'L' : 'Local',
}


def parse_route_table(lines):
    """
    Parses 'show route' output.

    Returns list of dicts:
    {
        'code'     : str,   # C, S, S*, O, B, etc.
        'type'     : str,   # Human-readable type
        'network'  : str,
        'mask'     : str,
        'ad_metric': str,   # e.g. '1/0' or '' if connected
        'nexthop'  : str,   # Next-hop IP or '' if connected
        'interface': str,
    }
    """
    routes = []

    for line in lines:
        if not line.strip():
            continue

        # Skip legend/header lines that start with known non-route text
        if line.lower().startswith(('codes:', 'gateway', 'routing')):
            continue

        match = RE_ROUTE.match(line)
        if match:
            code = match.group(1).strip()
            network = match.group(2)
            mask = match.group(3)
            ad_metric = match.group(4) or ''
            nexthop = match.group(5) or ''
            interface = match.group(6) or ''

            # Resolve human-readable type
            route_type = ROUTE_CODES.get(code, code)

            routes.append({
                'code'     : code,
                'type'     : route_type,
                'network'  : network,
                'mask'     : mask,
                'ad_metric': ad_metric,
                'nexthop'  : nexthop,
                'interface': interface,
            })

    return routes


def print_route_table(routes):
    """
    Prints route table grouped by type with migration notes.
    """
    print("=" * 80)
    print("  ROUTING TABLE  (show route)")
    print("=" * 80)

    if not routes:
        print("  [WARNING] No routes parsed. Check section content.")
        print("  Expected format: S  10.0.0.0 255.0.0.0 [1/0] via 192.168.1.1, outside")
        return

    # Group by type for organized output
    from collections import defaultdict
    grouped = defaultdict(list)
    for r in routes:
        grouped[r['type']].append(r)

    type_order = ['Connected', 'Local', 'Static', 'Static Default',
                  'OSPF', 'OSPF Default', 'BGP', 'EIGRP', 'IS-IS']

    # Print remaining types not in order list
    all_types = type_order + [t for t in grouped if t not in type_order]

    for rtype in all_types:
        if rtype not in grouped:
            continue

        rlist = grouped[rtype]
        print(f"\n  ── {rtype.upper()} ({len(rlist)} route(s)) " + "─" * 30)
        print(f"  {'NETWORK':<20} {'MASK':<18} {'NEXT-HOP':<18} {'INTERFACE':<15} {'AD/METRIC'}")
        print(f"  {'-'*19} {'-'*17} {'-'*17} {'-'*14} {'-'*10}")

        for r in rlist:
            nexthop = r['nexthop'] if r['nexthop'] else 'directly connected'
            print(f"  {r['network']:<20} {r['mask']:<18} "
                  f"{nexthop:<18} {r['interface']:<15} {r['ad_metric']}")

    # Summary
    print(f"\n  Total routes     : {len(routes)}")

    static_count = len(grouped.get('Static', [])) + len(grouped.get('Static Default', []))
    dynamic_types = [t for t in grouped if t not in
                     ('Connected', 'Local', 'Static', 'Static Default')]

    print(f"  Static routes    : {static_count}")

    if dynamic_types:
        print(f"  Dynamic routing  : {', '.join(dynamic_types)}")
        print()
        print("  [MIGRATION NOTE] Dynamic routing protocols detected.")
        print("  These must be reconfigured in FMC — ASA routing config")
        print("  does not migrate automatically via FMT.")
    else:
        print("  Dynamic routing  : None detected")

    # Default route flag
    if 'Static Default' in grouped or any(
        r['network'] == '0.0.0.0' for r in routes
    ):
        default = next(
            (r for r in routes if r['network'] == '0.0.0.0'), None
        )
        if default:
            print(f"\n  [DEFAULT ROUTE]  0.0.0.0/0 via {default['nexthop']}"
                  f" ({default['interface']})")
    print()


# ════════════════════════════════════════════════════════════
# PARSER 3: VPN-SESSIONDB-SUMMARY
# ════════════════════════════════════════════════════════════

def parse_vpn_summary(lines):
    """
    Parses 'show vpn-sessiondb summary' output.

    Returns list of dicts:
    {
        'session_type': str,
        'total'       : int,
        'active'      : int,
    }

    Also returns a list of session type headers found,
    which are used as migration reference for FTD RA VPN design.
    """
    sessions = []
    session_types_found = []

    for line in lines:
        if not line.strip():
            continue

        # Capture session type headers
        type_match = RE_VPN_TYPE.match(line)
        if type_match:
            session_types_found.append(type_match.group(1).strip())
            continue

        # Capture active session count lines
        count_match = RE_VPN_SUMMARY.match(line)
        if count_match:
            sessions.append({
                'session_type': count_match.group(1).strip(),
                'total'       : int(count_match.group(2)),
                'active'      : int(count_match.group(3)),
            })

    return sessions, session_types_found


def print_vpn_summary(sessions, session_types_found):
    """
    Prints VPN session summary with migration planning notes.
    """
    print("=" * 65)
    print("  VPN SESSION SUMMARY  (show vpn-sessiondb summary)")
    print("=" * 65)

    if not sessions and not session_types_found:
        print("  [INFO] No active VPN sessions detected.")
        print("  This may indicate no active sessions at time of capture,")
        print("  or that the section content did not match expected format.")
        return

    # Session type headers found
    if session_types_found:
        print(f"\n  Session types present in database:")
        for st in session_types_found:
            print(f"    • {st}")

    # Active session counts
    if sessions:
        print(f"\n  {'SESSION TYPE':<35} {'TOTAL':<10} {'ACTIVE'}")
        print(f"  {'-'*34} {'-'*9} {'-'*10}")

        total_active = 0
        for s in sessions:
            print(f"  {s['session_type']:<35} {s['total']:<10} {s['active']}")
            total_active += s['active']

        print(f"\n  Total active sessions : {total_active}")

    # Migration notes based on what's found
    print()
    vpn_types_lower = [s['session_type'].lower() for s in sessions]
    type_headers_lower = [t.lower() for t in session_types_found]
    all_vpn_lower = vpn_types_lower + type_headers_lower

    if any('anyconnect' in v for v in all_vpn_lower):
        print("  [MIGRATION NOTE] AnyConnect sessions detected.")
        print("  RA VPN must be configured in FMC before cutover.")
        print("  Plan maintenance window — active sessions will drop")
        print("  during migration unless clustering/hitless failover applies.")

    if any('ikev1' in v for v in all_vpn_lower):
        print()
        print("  [MIGRATION NOTE] IKEv1 Site-to-Site sessions detected.")
        print("  FTD supports IKEv1 but Cisco recommends migrating to IKEv2.")
        print("  Coordinate with remote peers before changing IKE version.")

    if any('ikev2' in v for v in all_vpn_lower):
        print()
        print("  [MIGRATION NOTE] IKEv2 sessions detected.")
        print("  IKEv2 migrates cleanly to FTD — verify crypto proposals")
        print("  match what is configured in RUNNING-CONFIG-CRYPTO section.")

    if any('site-to-site' in v or 'l2l' in v for v in all_vpn_lower):
        print()
        print("  [MIGRATION NOTE] Site-to-Site tunnels active.")
        print("  These will drop during FTD cutover. Notify remote peers.")
    print()


# ════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════

def print_header():
    print()
    print("=" * 65)
    print("  ASA MIGRATION PARSER — PHASE 3")
    print("  Parsing: Interface Brief | Routes | VPN Summary")
    print("=" * 65)
    print()


def main():
    if len(sys.argv) != 2:
        print("Usage: python asa_parser_p3.py <path_to_log_file>")
        print("Example: python asa_parser_p3.py asa_logs.txt")
        sys.exit(1)

    filepath = sys.argv[1]

    if not os.path.isfile(filepath):
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)

    if os.path.getsize(filepath) == 0:
        print(f"[ERROR] File is empty: {filepath}")
        sys.exit(1)

    print_header()

    # ── Extract all sections ─────────────────────────────────
    sections_data = extract_sections(filepath)

    # ── Parse and print each section ────────────────────────

    # 1. Interface IP Brief
    intf_lines = sections_data.get("INTERFACE-IP-BRIEF", [])
    if intf_lines:
        interfaces = parse_interface_brief(intf_lines)
        print_interface_brief(interfaces)
    else:
        print("  [SKIPPED] INTERFACE-IP-BRIEF — section empty or not found.\n")

    # 2. Route Table
    route_lines = sections_data.get("ROUTE", [])
    if route_lines:
        routes = parse_route_table(route_lines)
        print_route_table(routes)
    else:
        print("  [SKIPPED] ROUTE — section empty or not found.\n")

    # 3. VPN Session Summary
    vpn_lines = sections_data.get("VPN-SESSIONDB-SUMMARY", [])
    if vpn_lines:
        sessions, session_types = parse_vpn_summary(vpn_lines)
        print_vpn_summary(sessions, session_types)
    else:
        print("  [SKIPPED] VPN-SESSIONDB-SUMMARY — section empty or not found.\n")


if __name__ == "__main__":
    main()
