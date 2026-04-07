# ============================================================
# ASA Migration Parser - Phase 3: Interface, Route, and
#                                  VPN/Crypto Live State
# ============================================================
# PURPOSE:
#   Parses all sections related to interface inventory, routing,
#   active VPN sessions, and live crypto SA state. This phase
#   provides the "what is running right now" picture that
#   complements the configuration analysis in Phase 4.
#
# PARSERS IN THIS FILE:
#   1.  INTERFACE-IP-BRIEF    — show interface ip brief
#   2.  INTERFACE             — show interface (verbose)
#   3.  ROUTE                 — show route
#   4.  VPN-SESSIONDB-SUMMARY — show vpn-sessiondb summary
#   5.  VPN-SESSIONDB-ANYCONNECT — show vpn-sessiondb anyconnect
#   6.  VPN-SESSIONDB-L2L     — show vpn-sessiondb l2l
#   7.  VPN-SESSIONDB-RATIO-ENC  — show vpn-sessiondb ratio encryption
#   8.  VPN-SESSIONDB-RATIO-PROTO— show vpn-sessiondb ratio protocol
#   9.  VPN-SESSIONDB-FULL    — show vpn-sessiondb full
#                               (superset; detail feeds same parser)
#   10. CRYPTO-ISAKMP-SA      — show crypto isakmp sa
#   11. CRYPTO-IKEv1-SA       — show crypto ikev1 sa
#   12. CRYPTO-IKEv2-SA       — show crypto ikev2 sa
#   13. CRYPTO-IPSEC-SA       — show crypto ipsec sa
#   14. CRYPTO-IPSEC-STATS    — show crypto ipsec policy stats
#   15. CRYPTO-ISAKMP-STATS   — show crypto isakmp stats
#
# USAGE:
#   python asa_parser_p3.py <path_to_log_file>
#
# FTD COMPATIBILITY BASELINE:
#   Verified for FMC/FTD 7.2.8 and 7.6.x (April 2026).
#   Live SA negotiated algorithm data is used by Phase 6 to
#   generate per-tunnel FMC action items in the Technical
#   Report and Crypto Remediation Report.
# ============================================================

import re
import sys
import os
from collections import defaultdict


# ════════════════════════════════════════════════════════════
# SECTION EXTRACTION
# ════════════════════════════════════════════════════════════

SECTION_PATTERN = re.compile(
    r'^!\s*===SECTION:\s*([A-Z0-9_\-]+)\s*===$',
    re.IGNORECASE
)


def extract_sections(filepath):
    """
    Reads the log file and returns { section_name: [lines] }.
    Leading whitespace preserved — structural in crypto/interface
    output.
    """
    sections_data = {}
    current_section = None

    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.rstrip('\n').rstrip('\r')
            stripped = line.strip()
            match = SECTION_PATTERN.match(stripped)
            if match:
                current_section = match.group(1).upper().strip()
                sections_data[current_section] = []
            elif current_section is not None:
                sections_data[current_section].append(line)

    return sections_data


# ════════════════════════════════════════════════════════════
# FTD ALGORITHM STATUS (mirrors p4 — standalone safe)
# ════════════════════════════════════════════════════════════

FTD_ESP_ENC = {
    'esp-des': 'REMOVED', 'esp-3des': 'REMOVED',
    'esp-aes': 'OK', 'esp-aes-192': 'OK', 'esp-aes-256': 'OK',
    'esp-aes-gcm': 'OK', 'esp-aes-gcm-192': 'OK',
    'esp-aes-gcm-256': 'OK', 'esp-null': 'OK',
    'des': 'REMOVED', '3des': 'REMOVED',
    'aes': 'OK', 'aes-192': 'OK', 'aes-256': 'OK',
    'aes-gcm': 'OK', 'aes-gcm-192': 'OK', 'aes-gcm-256': 'OK',
    'null': 'OK',
}
FTD_ESP_INT = {
    'esp-md5-hmac': 'REMOVED', 'md5': 'REMOVED', 'md5-96': 'REMOVED',
    'esp-sha-hmac': 'DEPRECATED', 'sha': 'DEPRECATED', 'sha-1': 'DEPRECATED',
    'esp-sha256-hmac': 'OK', 'sha256': 'OK', 'sha-256': 'OK',
    'esp-sha384-hmac': 'OK', 'sha384': 'OK', 'sha-384': 'OK',
    'esp-sha512-hmac': 'OK', 'sha512': 'OK', 'sha-512': 'OK',
    'esp-none': 'OK', 'null': 'OK', 'none': 'OK',
}
FTD_IKE_ENC = {
    'des': 'REMOVED', '3des': 'REMOVED',
    'aes': 'OK', 'aes-192': 'OK', 'aes-256': 'OK',
    'aes-gcm': 'OK', 'aes-gcm-192': 'OK', 'aes-gcm-256': 'OK',
}
FTD_IKE_HASH = {
    'md5': 'REMOVED', 'sha': 'DEPRECATED', 'sha-1': 'DEPRECATED',
    'sha256': 'OK', 'sha384': 'OK', 'sha512': 'OK',
    'sha-256': 'OK', 'sha-384': 'OK', 'sha-512': 'OK',
    'null': 'OK',
}
FTD_DH = {
    '1': 'REMOVED', '2': 'REMOVED', '5': 'DEPRECATED',
    '14': 'OK', '19': 'OK', '20': 'OK', '21': 'OK', '24': 'REMOVED',
}


def _alg_status(alg, table):
    return table.get(alg.lower().strip(), 'UNKNOWN')


def _worst_status(statuses):
    """Returns the worst status from a list of status strings."""
    if 'REMOVED' in statuses:
        return 'REMOVED'
    if 'DEPRECATED' in statuses:
        return 'DEPRECATED'
    if 'UNKNOWN' in statuses:
        return 'UNKNOWN'
    return 'OK'


def _flag(status):
    return {
        'REMOVED': '[REMOVED]', 'DEPRECATED': '[DEPRECATED]',
        'OK': '[OK]', 'UNKNOWN': '[UNKNOWN]',
    }.get(status, '[UNKNOWN]')


# ════════════════════════════════════════════════════════════
# PARSER 1: INTERFACE-IP-BRIEF
# show interface ip brief
# ════════════════════════════════════════════════════════════

RE_INTF_BRIEF = re.compile(
    r'^(\S+)\s+'
    r'([\d\.]+|unassigned)\s+'
    r'(YES|NO)\s+'
    r'(\S+)\s+'
    r'([\w\s]+?)\s{2,}'
    r'(up|down)',
    re.IGNORECASE
)


def parse_interface_brief(lines):
    """
    Parses 'show interface ip brief' output.

    Returns list of dicts:
      interface, ip, ok, method, status, protocol
    """
    interfaces = []
    for line in lines:
        s = line.strip()
        if not s:
            continue
        if s.lower().startswith('interface') and 'ip-address' in s.lower():
            continue
        m = RE_INTF_BRIEF.match(s)
        if m:
            interfaces.append({
                'interface': m.group(1),
                'ip'       : m.group(2),
                'ok'       : m.group(3),
                'method'   : m.group(4),
                'status'   : m.group(5).strip(),
                'protocol' : m.group(6),
            })
    return interfaces


def print_interface_brief(interfaces):
    print("=" * 75)
    print("  INTERFACE INVENTORY  (show interface ip brief)")
    print("=" * 75)

    if not interfaces:
        print("  [WARNING] No interfaces parsed. Check section content.")
        return

    print(f"\n  {'INTERFACE':<30} {'IP ADDRESS':<18} {'STATUS':<12}"
          f" {'PROTOCOL':<10} {'FLAGS'}")
    print(f"  {'-'*29} {'-'*17} {'-'*11} {'-'*9} {'-'*20}")

    down_count = unassigned_count = 0

    for i in interfaces:
        flags = []
        if i['status'].lower() != 'up':
            flags.append('DOWN')
            down_count += 1
        if i['ip'].lower() == 'unassigned':
            flags.append('NO IP')
            unassigned_count += 1
        if 'admin' in i['status'].lower():
            flags.append('ADMIN-DOWN')

        print(f"  {i['interface']:<30} {i['ip']:<18} "
              f"{i['status']:<12} {i['protocol']:<10} "
              f"{' | '.join(flags)}")

    print(f"\n  Total interfaces : {len(interfaces)}")
    print(f"  Down/Admin-down  : {down_count}")
    print(f"  No IP assigned   : {unassigned_count}")

    if down_count:
        print()
        print("  [MIGRATION NOTE] Down interfaces detected.")
        print("  Confirm whether these need to be migrated or")
        print("  decommissioned on the FTD 3110 HA pair.")
    print()


# ════════════════════════════════════════════════════════════
# PARSER 2: INTERFACE (verbose)
# show interface
# ════════════════════════════════════════════════════════════
# Expected format (per Cisco ASA CLI Reference):
#
# Interface GigabitEthernet0/0 "outside", is up, line protocol is up
#   Hardware is i82546GB rev03, BW 1000 Mbps, DLY 10 usec
#   Description: WAN uplink
#   MAC address 0000.0000.0001, MTU 1500
#   IP address 203.0.113.1, subnet mask 255.255.255.0
#   264589 packets input, 48766564 bytes, 0 no buffer
#   0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
#   286731 packets output, 52413748 bytes, 0 underruns
#   0 output errors, 0 collisions, 0 interface resets

RE_INTF_HEADER = re.compile(
    r'^Interface\s+(\S+)\s+"([^"]*)".*?is\s+(up|down|administratively down)',
    re.IGNORECASE
)
RE_INTF_LINE_PROTO = re.compile(
    r'line protocol is\s+(up|down)',
    re.IGNORECASE
)
RE_INTF_BW = re.compile(
    r'BW\s+(\d+)\s+(\w+)',
    re.IGNORECASE
)
RE_INTF_DESC = re.compile(
    r'^\s+Description:\s+(.+)',
    re.IGNORECASE
)
RE_INTF_MAC = re.compile(
    r'MAC address\s+(\S+)',
    re.IGNORECASE
)
RE_INTF_MTU = re.compile(
    r'MTU\s+(\d+)',
    re.IGNORECASE
)
RE_INTF_IP = re.compile(
    r'IP address\s+([\d\.]+),\s*subnet mask\s+([\d\.]+)',
    re.IGNORECASE
)
RE_INTF_INPUT_PKT = re.compile(
    r'(\d+)\s+packets input,\s+(\d+)\s+bytes',
    re.IGNORECASE
)
RE_INTF_OUTPUT_PKT = re.compile(
    r'(\d+)\s+packets output,\s+(\d+)\s+bytes',
    re.IGNORECASE
)
RE_INTF_INPUT_ERR = re.compile(
    r'(\d+)\s+input errors,\s+(\d+)\s+CRC',
    re.IGNORECASE
)
RE_INTF_OUTPUT_ERR = re.compile(
    r'(\d+)\s+output errors,\s+(\d+)\s+collisions,\s+(\d+)\s+interface resets',
    re.IGNORECASE
)
RE_INTF_RESETS = re.compile(
    r'(\d+)\s+interface resets',
    re.IGNORECASE
)
RE_INTF_DUPLEX = re.compile(
    r'(Full|Half|Auto)-duplex',
    re.IGNORECASE
)
RE_INTF_SPEED = re.compile(
    r'(\d+(?:\.\d+)?(?:Mb|Gb|kb)ps)',
    re.IGNORECASE
)


def parse_interface_verbose(lines):
    """
    Parses 'show interface' verbose output.

    Returns list of dicts per interface:
      name, nameif, status, line_protocol, description,
      ip, mask, mac, mtu, bandwidth, duplex, speed,
      input_packets, input_bytes, input_errors, crc_errors,
      output_packets, output_bytes, output_errors,
      interface_resets
    """
    interfaces = []
    current = None

    for line in lines:
        s = line.strip()
        if not s:
            continue

        # ── New interface block ───────────────────────────────
        m = RE_INTF_HEADER.match(s)
        if m:
            current = {
                'name'            : m.group(1),
                'nameif'          : m.group(2),
                'status'          : m.group(3).lower(),
                'line_protocol'   : None,
                'description'     : None,
                'ip'              : None,
                'mask'            : None,
                'mac'             : None,
                'mtu'             : None,
                'bandwidth'       : None,
                'duplex'          : None,
                'speed'           : None,
                'input_packets'   : None,
                'input_bytes'     : None,
                'input_errors'    : None,
                'crc_errors'      : None,
                'output_packets'  : None,
                'output_bytes'    : None,
                'output_errors'   : None,
                'interface_resets': None,
            }
            interfaces.append(current)

            lp = RE_INTF_LINE_PROTO.search(s)
            if lp:
                current['line_protocol'] = lp.group(1).lower()
            continue

        if current is None:
            continue

        # ── Sub-fields ────────────────────────────────────────
        lp = RE_INTF_LINE_PROTO.search(s)
        if lp:
            current['line_protocol'] = lp.group(1).lower()

        desc = RE_INTF_DESC.match(line)
        if desc:
            current['description'] = desc.group(1).strip()

        m = RE_INTF_IP.search(s)
        if m:
            current['ip']   = m.group(1)
            current['mask'] = m.group(2)

        m = RE_INTF_MAC.search(s)
        if m:
            current['mac'] = m.group(1)

        m = RE_INTF_MTU.search(s)
        if m:
            current['mtu'] = m.group(1)

        m = RE_INTF_BW.search(s)
        if m:
            current['bandwidth'] = f"{m.group(1)} {m.group(2)}"

        m = RE_INTF_DUPLEX.search(s)
        if m:
            current['duplex'] = m.group(1)

        m = RE_INTF_SPEED.search(s)
        if m:
            current['speed'] = m.group(1)

        m = RE_INTF_INPUT_PKT.search(s)
        if m:
            current['input_packets'] = int(m.group(1))
            current['input_bytes']   = int(m.group(2))

        m = RE_INTF_OUTPUT_PKT.search(s)
        if m:
            current['output_packets'] = int(m.group(1))
            current['output_bytes']   = int(m.group(2))

        m = RE_INTF_INPUT_ERR.search(s)
        if m:
            current['input_errors'] = int(m.group(1))
            current['crc_errors']   = int(m.group(2))

        m = RE_INTF_OUTPUT_ERR.search(s)
        if m:
            current['output_errors']    = int(m.group(1))
            current['interface_resets'] = int(m.group(3))

    return interfaces


def print_interface_verbose(interfaces):
    print("=" * 78)
    print("  INTERFACE DETAIL  (show interface)")
    print("=" * 78)

    if not interfaces:
        print("  [WARNING] No verbose interface data parsed.")
        return

    error_intfs = [
        i for i in interfaces
        if (i['input_errors'] or 0) > 0
        or (i['crc_errors'] or 0) > 0
        or (i['output_errors'] or 0) > 0
        or (i['interface_resets'] or 0) > 10
    ]

    for i in interfaces:
        status_flag = ''
        if i['status'] != 'up':
            status_flag = f"  [DOWN]"
        elif i['line_protocol'] == 'down':
            status_flag = f"  [LINE-PROTO-DOWN]"

        nameif_str = f'"{i["nameif"]}"' if i['nameif'] else '(no nameif)'
        print(f"\n  ── {i['name']} {nameif_str}{status_flag}")

        if i['description']:
            print(f"     Description    : {i['description']}")
        print(f"     Status         : {i['status']} / "
              f"line protocol {i['line_protocol'] or 'unknown'}")
        if i['ip']:
            print(f"     IP Address     : {i['ip']}  mask {i['mask']}")
        if i['mac']:
            print(f"     MAC Address    : {i['mac']}")
        if i['mtu']:
            print(f"     MTU            : {i['mtu']} bytes")
        if i['bandwidth']:
            print(f"     Bandwidth      : {i['bandwidth']}")
        if i['duplex'] or i['speed']:
            ds = ' / '.join(
                x for x in [i['duplex'], i['speed']] if x
            )
            print(f"     Duplex/Speed   : {ds}")

        if i['input_packets'] is not None:
            print(f"     Input          : {i['input_packets']:,} pkts"
                  f"  {i['input_bytes']:,} bytes")
        if i['output_packets'] is not None:
            print(f"     Output         : {i['output_packets']:,} pkts"
                  f"  {i['output_bytes']:,} bytes")

        if (i['input_errors'] or 0) > 0 or (i['crc_errors'] or 0) > 0:
            print(f"     [FLAG] Input errors  : {i['input_errors']}  "
                  f"CRC: {i['crc_errors']}")
        if (i['output_errors'] or 0) > 0:
            print(f"     [FLAG] Output errors : {i['output_errors']}")
        if (i['interface_resets'] or 0) > 10:
            print(f"     [FLAG] Interface resets: {i['interface_resets']}"
                  f"  — investigate before migration")

    if error_intfs:
        print(f"\n  {'='*78}")
        print(f"  INTERFACES WITH ERRORS ({len(error_intfs)})")
        print(f"  {'='*78}")
        print("  [MIGRATION NOTE] Interface errors detected.")
        print("  Investigate and resolve before cutover — errors may")
        print("  indicate physical layer issues that will persist on FTD.")
        for i in error_intfs:
            print(f"    {i['name']} ({i['nameif'] or 'no nameif'}): "
                  f"in_err={i['input_errors']} crc={i['crc_errors']} "
                  f"out_err={i['output_errors']} resets={i['interface_resets']}")
    print()


# ════════════════════════════════════════════════════════════
# PARSER 3: ROUTE TABLE
# show route
# ════════════════════════════════════════════════════════════

RE_ROUTE = re.compile(
    r'^([A-Za-z\*\s]{1,5})\s+'
    r'([\d\.]+)\s+'
    r'([\d\.]+)\s+'
    r'(?:\[(\d+/\d+)\]\s+)?'
    r'(?:via\s+([\d\.]+),?\s*)?'
    r'(?:is directly connected,\s*)?'
    r'(\S+)?'
)

ROUTE_CODES = {
    'C': 'Connected', 'S': 'Static', 'S*': 'Static Default',
    'O': 'OSPF', 'O*': 'OSPF Default', 'B': 'BGP',
    'i': 'IS-IS', 'D': 'EIGRP', 'EX': 'EIGRP External', 'L': 'Local',
}


def parse_route_table(lines):
    """
    Parses 'show route' output.

    Returns list of dicts:
      code, type, network, mask, ad_metric, nexthop, interface
    """
    routes = []
    for line in lines:
        s = line.strip()
        if not s:
            continue
        if s.lower().startswith(('codes:', 'gateway', 'routing')):
            continue
        m = RE_ROUTE.match(s)
        if m:
            code = m.group(1).strip()
            routes.append({
                'code'     : code,
                'type'     : ROUTE_CODES.get(code, code),
                'network'  : m.group(2),
                'mask'     : m.group(3),
                'ad_metric': m.group(4) or '',
                'nexthop'  : m.group(5) or '',
                'interface': m.group(6) or '',
            })
    return routes


def print_route_table(routes):
    print("=" * 80)
    print("  ROUTING TABLE  (show route)")
    print("=" * 80)

    if not routes:
        print("  [WARNING] No routes parsed. Check section content.")
        return

    grouped = defaultdict(list)
    for r in routes:
        grouped[r['type']].append(r)

    type_order = [
        'Connected', 'Local', 'Static', 'Static Default',
        'OSPF', 'OSPF Default', 'BGP', 'EIGRP', 'IS-IS',
    ]
    all_types = type_order + [t for t in grouped if t not in type_order]

    for rtype in all_types:
        if rtype not in grouped:
            continue
        rlist = grouped[rtype]
        print(f"\n  ── {rtype.upper()} ({len(rlist)} route(s)) " + "─" * 30)
        print(f"  {'NETWORK':<20} {'MASK':<18} {'NEXT-HOP':<18}"
              f" {'INTERFACE':<15} {'AD/METRIC'}")
        print(f"  {'-'*19} {'-'*17} {'-'*17} {'-'*14} {'-'*10}")
        for r in rlist:
            nh = r['nexthop'] if r['nexthop'] else 'directly connected'
            print(f"  {r['network']:<20} {r['mask']:<18} "
                  f"{nh:<18} {r['interface']:<15} {r['ad_metric']}")

    static_count = (
        len(grouped.get('Static', [])) +
        len(grouped.get('Static Default', []))
    )
    dynamic_types = [
        t for t in grouped
        if t not in ('Connected', 'Local', 'Static', 'Static Default')
    ]

    print(f"\n  Total routes     : {len(routes)}")
    print(f"  Static routes    : {static_count}")

    if dynamic_types:
        print(f"  Dynamic routing  : {', '.join(dynamic_types)}")
        print()
        print("  [MIGRATION NOTE] Dynamic routing protocols detected.")
        print("  These must be reconfigured in FMC — ASA routing config")
        print("  does not migrate automatically via FMT.")
    else:
        print("  Dynamic routing  : None detected")

    default = next((r for r in routes if r['network'] == '0.0.0.0'), None)
    if default:
        print(f"\n  [DEFAULT ROUTE]  0.0.0.0/0 via {default['nexthop']}"
              f" ({default['interface']})")
    print()


# ════════════════════════════════════════════════════════════
# PARSER 4: VPN-SESSIONDB-SUMMARY
# show vpn-sessiondb summary
# ════════════════════════════════════════════════════════════

RE_VPN_DATA_ROW = re.compile(
    r'^(\s*)([A-Za-z0-9/\s\(\)\-\.]+?)'
    r'\s*:\s*(\d+)'
    r'\s*:\s*(\d+)'
    r'(?:\s*:\s*(\d+))?'
    r'(?:\s*:\s*(\d+))?'
    r'\s*$'
)
RE_VPN_TOTAL    = re.compile(
    r'Total Active and Inactive\s*:\s*(\d+).*?Total Cumulative\s*:\s*(\d+)',
    re.IGNORECASE
)
RE_VPN_CAPACITY = re.compile(
    r'Device Total VPN Capacity\s*:\s*(\d+)', re.IGNORECASE
)
RE_VPN_LOAD     = re.compile(
    r'Device Load\s*:\s*(\d+)%', re.IGNORECASE
)


def parse_vpn_summary(lines):
    """
    Parses 'show vpn-sessiondb summary' output.

    Returns:
      sessions : list of session-type dicts
      totals   : dict with total_active, capacity, load_pct
    """
    sessions = []
    totals = {
        'total_active': None, 'total_cumulative': None,
        'capacity': None, 'load_pct': None,
    }

    for line in lines:
        s = line.strip()
        if not s or re.match(r'^-+$', s):
            continue
        if s.lower() == 'vpn session summary':
            continue
        if 'active' in s.lower() and 'cumulative' in s.lower() \
                and not re.search(r':\s*\d+', s):
            continue

        m = RE_VPN_TOTAL.search(s)
        if m:
            totals['total_active']     = int(m.group(1))
            totals['total_cumulative'] = int(m.group(2))
            continue

        m = RE_VPN_CAPACITY.search(s)
        if m:
            totals['capacity'] = int(m.group(1))
            continue

        m = RE_VPN_LOAD.search(s)
        if m:
            totals['load_pct'] = int(m.group(1))
            continue

        m = RE_VPN_DATA_ROW.match(line)
        if m:
            sessions.append({
                'label'     : m.group(2).strip(),
                'is_child'  : len(m.group(1)) > 0,
                'active'    : int(m.group(3)),
                'cumulative': int(m.group(4)),
                'peak'      : int(m.group(5)) if m.group(5) else None,
                'inactive'  : int(m.group(6)) if m.group(6) else None,
            })

    return sessions, totals


def print_vpn_summary(sessions, totals):
    print("=" * 70)
    print("  VPN SESSION SUMMARY  (show vpn-sessiondb summary)")
    print("=" * 70)

    if not sessions and totals['total_active'] is None:
        print("  [WARNING] No VPN session data parsed.")
        return

    print(f"\n  {'SESSION TYPE':<35} {'ACTIVE':>8} {'CUMULATIVE':>12}"
          f" {'PEAK':>8} {'INACTIVE':>10}")
    print(f"  {'-'*34} {'-'*8} {'-'*12} {'-'*8} {'-'*10}")

    for s in sessions:
        label    = ('  ' + s['label']) if s['is_child'] else s['label']
        peak     = str(s['peak'])     if s['peak']     is not None else '—'
        inactive = str(s['inactive']) if s['inactive'] is not None else '—'
        print(f"  {label:<35} {s['active']:>8} "
              f"{s['cumulative']:>12,} {peak:>8} {inactive:>10}")

    print(f"\n  {'-'*70}")
    if totals['total_active'] is not None:
        print(f"  Total Active + Inactive  : {totals['total_active']}")
    if totals['total_cumulative'] is not None:
        print(f"  Total Cumulative         : {totals['total_cumulative']:,}")
    if totals['capacity'] is not None:
        print(f"  Device VPN Capacity      : {totals['capacity']}")
    if totals['load_pct'] is not None:
        print(f"  Device Load              : {totals['load_pct']}%")
        if totals['load_pct'] >= 80:
            print()
            print("  [WARNING] Device load >= 80%. Verify the FTD 3110 HA")
            print("  pair is sized to handle this VPN load before cutover.")

    labels_lower    = [s['label'].lower() for s in sessions]
    has_anyconnect  = any('anyconnect' in l for l in labels_lower)
    has_s2s         = any('site-to-site' in l for l in labels_lower)
    has_ikev1       = any('ikev1' in l for l in labels_lower)
    has_ikev2       = any('ikev2' in l for l in labels_lower)

    anyconnect_active = next(
        (s['active'] for s in sessions
         if 'anyconnect client' in s['label'].lower()
         and not s['is_child']), 0
    )
    s2s_active = next(
        (s['active'] for s in sessions
         if 'site-to-site' in s['label'].lower()
         and not s['is_child']), 0
    )

    print(f"\n  {'='*70}")
    print("  MIGRATION NOTES")
    print(f"  {'='*70}")

    if has_anyconnect:
        print(f"\n  [ANYCONNECT]  {anyconnect_active} active session(s)")
        print("  RA VPN must be fully configured in FMC prior to cutover.")
        print("  Active sessions will disconnect during migration.")
        print("  Plan a maintenance window or coordinate with end users.")

    if has_s2s:
        print(f"\n  [SITE-TO-SITE]  {s2s_active} active tunnel(s)")
        print("  All S2S tunnels will drop during FTD cutover.")
        print("  Notify remote peer administrators before migration.")

    if has_ikev1:
        print()
        print("  [IKEv1 DETECTED]")
        print("  FTD supports IKEv1 but Cisco recommends migrating to IKEv2.")
        print("  Review RUNNING-CONFIG-CRYPTO for weak proposals:")
        print("  DES, 3DES, MD5, DH group 1/2/5 — FTD may reject these.")

    if has_ikev2:
        print()
        print("  [IKEv2 DETECTED]")
        print("  IKEv2 migrates cleanly to FTD.")
        print("  Verify crypto proposals in RUNNING-CONFIG-CRYPTO section.")

    if not has_anyconnect and not has_s2s:
        print("\n  [INFO] No AnyConnect or Site-to-Site sessions detected.")
        print("  Confirm VPN is not in use or was not active at capture time.")
    print()


# ════════════════════════════════════════════════════════════
# PARSER 5: VPN-SESSIONDB-ANYCONNECT
# show vpn-sessiondb anyconnect
# ════════════════════════════════════════════════════════════
# Per-session fields from ASA output:
# Username     : user@domain.com       Index        : 12345
# Assigned IP  : 10.1.1.5              Public IP    : 203.0.113.10
# Protocol     : AnyConnect-Parent SSL-Tunnel DTLS-Tunnel
# License      : AnyConnect Premium
# Encryption   : AnyConnect-Parent: (1)none  SSL-Tunnel: (1)AES-GCM-256
#                DTLS-Tunnel: (1)AES-GCM-256
# Hashing      : AnyConnect-Parent: (1)none  SSL-Tunnel: (1)SHA384
#                DTLS-Tunnel: (1)SHA384
# Bytes Tx     : 12345678              Bytes Rx     : 87654321
# Login Time   : 10:00:00 UTC Mon Apr 07 2026
# Duration     : 0h:30m:00s
# Inactivity   : 0h:00m:00s
# NAC Result   : Unknown
# VLAN Mapping : N/A                   VLAN         : none

RE_AC_USERNAME   = re.compile(r'^Username\s*:\s*(\S+)', re.IGNORECASE)
RE_AC_ASSIGNED   = re.compile(r'Assigned IP\s*:\s*([\d\.]+)', re.IGNORECASE)
RE_AC_PUBLIC     = re.compile(r'Public IP\s*:\s*([\d\.]+)', re.IGNORECASE)
RE_AC_PROTOCOL   = re.compile(r'^Protocol\s*:\s*(.+)', re.IGNORECASE)
RE_AC_ENCRYPTION = re.compile(r'^Encryption\s*:\s*(.+)', re.IGNORECASE)
RE_AC_HASHING    = re.compile(r'^Hashing\s*:\s*(.+)', re.IGNORECASE)
RE_AC_BYTES_TX   = re.compile(r'Bytes Tx\s*:\s*([\d,]+)', re.IGNORECASE)
RE_AC_BYTES_RX   = re.compile(r'Bytes Rx\s*:\s*([\d,]+)', re.IGNORECASE)
RE_AC_DURATION   = re.compile(r'^Duration\s*:\s*(.+)', re.IGNORECASE)
RE_AC_LOGIN      = re.compile(r'^Login Time\s*:\s*(.+)', re.IGNORECASE)


def parse_vpn_anyconnect(lines):
    """
    Parses 'show vpn-sessiondb anyconnect' per-session output.

    Returns list of dicts per session:
      username, assigned_ip, public_ip, protocol,
      encryption, hashing, bytes_tx, bytes_rx,
      duration, login_time
    """
    sessions = []
    current  = None

    for line in lines:
        s = line.strip()
        if not s or re.match(r'^-+$', s):
            continue

        m = RE_AC_USERNAME.match(s)
        if m:
            current = {
                'username'    : m.group(1),
                'assigned_ip' : None,
                'public_ip'   : None,
                'protocol'    : None,
                'encryption'  : None,
                'hashing'     : None,
                'bytes_tx'    : None,
                'bytes_rx'    : None,
                'duration'    : None,
                'login_time'  : None,
            }
            sessions.append(current)
            continue

        if current is None:
            continue

        m = RE_AC_ASSIGNED.search(s)
        if m:
            current['assigned_ip'] = m.group(1)

        m = RE_AC_PUBLIC.search(s)
        if m:
            current['public_ip'] = m.group(1)

        m = RE_AC_PROTOCOL.match(s)
        if m:
            current['protocol'] = m.group(1).strip()

        m = RE_AC_ENCRYPTION.match(s)
        if m:
            current['encryption'] = m.group(1).strip()

        m = RE_AC_HASHING.match(s)
        if m:
            current['hashing'] = m.group(1).strip()

        m = RE_AC_BYTES_TX.search(s)
        if m:
            current['bytes_tx'] = m.group(1).replace(',', '')

        m = RE_AC_BYTES_RX.search(s)
        if m:
            current['bytes_rx'] = m.group(1).replace(',', '')

        m = RE_AC_DURATION.match(s)
        if m:
            current['duration'] = m.group(1).strip()

        m = RE_AC_LOGIN.match(s)
        if m:
            current['login_time'] = m.group(1).strip()

    return sessions


def print_vpn_anyconnect(sessions):
    print("=" * 78)
    print("  ANYCONNECT SESSION DETAIL  (show vpn-sessiondb anyconnect)")
    print("=" * 78)

    if not sessions:
        print("  [INFO] No active AnyConnect sessions at capture time.")
        print()
        return

    print(f"\n  Active sessions captured: {len(sessions)}")
    print()
    print(f"  {'USERNAME':<30} {'ASSIGNED IP':<16} {'PUBLIC IP':<16}"
          f" {'DURATION'}")
    print(f"  {'-'*29} {'-'*15} {'-'*15} {'-'*15}")

    for s in sessions:
        print(f"  {s['username']:<30} "
              f"{s['assigned_ip'] or '—':<16} "
              f"{s['public_ip'] or '—':<16} "
              f"{s['duration'] or '—'}")

    print()
    print("  [MIGRATION NOTE] All active AnyConnect sessions will")
    print("  disconnect at FTD cutover. Coordinate with these users")
    print("  or schedule the cutover window outside business hours.")
    print()


# ════════════════════════════════════════════════════════════
# PARSER 6: VPN-SESSIONDB-L2L
# show vpn-sessiondb l2l
# ════════════════════════════════════════════════════════════
# Per-tunnel fields from ASA output:
# Session Type: LAN-to-LAN
#
# Connection   : 203.0.113.50
# Index        : 9
# IP Addr      : 203.0.113.50
# Protocol     : IKEv2 IPsec
# Encryption   : IKEv2: (1)AES256  IPsec: (1)AES256
# Hashing      : IKEv2: (1)SHA384  IPsec: (1)SHA384
# Bytes Tx     : 1234567            Bytes Rx     : 7654321
# Login Time   : 08:00:00 UTC Mon Apr 07 2026
# Duration     : 2h:30m:00s

RE_L2L_CONNECTION = re.compile(r'^Connection\s*:\s*(\S+)', re.IGNORECASE)
RE_L2L_INDEX      = re.compile(r'^Index\s*:\s*(\d+)', re.IGNORECASE)
RE_L2L_IP         = re.compile(r'^IP Addr\s*:\s*([\d\.]+)', re.IGNORECASE)
RE_L2L_PROTOCOL   = re.compile(r'^Protocol\s*:\s*(.+)', re.IGNORECASE)
RE_L2L_ENCRYPTION = re.compile(r'^Encryption\s*:\s*(.+)', re.IGNORECASE)
RE_L2L_HASHING    = re.compile(r'^Hashing\s*:\s*(.+)', re.IGNORECASE)
RE_L2L_BYTES_TX   = re.compile(r'Bytes Tx\s*:\s*([\d,]+)', re.IGNORECASE)
RE_L2L_BYTES_RX   = re.compile(r'Bytes Rx\s*:\s*([\d,]+)', re.IGNORECASE)
RE_L2L_DURATION   = re.compile(r'^Duration\s*:\s*(.+)', re.IGNORECASE)
RE_L2L_LOGIN      = re.compile(r'^Login Time\s*:\s*(.+)', re.IGNORECASE)


def _parse_l2l_algorithms(enc_str, hash_str):
    """
    Extracts IKE and IPsec algorithms from the Encryption/Hashing
    field strings. Returns dicts with ike and ipsec entries.

    Example enc_str: "IKEv2: (1)AES256  IPsec: (1)AES256"
    Example hash_str: "IKEv2: (1)SHA384  IPsec: (1)SHA384"
    """
    def extract(text, prefix):
        """Pull algo tokens after a prefix like 'IKEv2:' or 'IPsec:'."""
        m = re.search(
            rf'{prefix}\s*:\s*(.+?)(?=IKEv[12]:|IPsec:|$)',
            text, re.IGNORECASE
        )
        if not m:
            return []
        raw = m.group(1)
        # Tokens like (1)AES256 → AES256
        tokens = re.findall(r'\(\d+\)(\S+)', raw)
        if not tokens:
            tokens = [t for t in raw.split() if t]
        return [t.lower() for t in tokens]

    enc_ike   = extract(enc_str or '',  r'IKEv[12]')
    enc_ipsec = extract(enc_str or '',  'IPsec')
    hsh_ike   = extract(hash_str or '', r'IKEv[12]')
    hsh_ipsec = extract(hash_str or '', 'IPsec')

    return {
        'ike_enc'   : enc_ike,
        'ipsec_enc' : enc_ipsec,
        'ike_hash'  : hsh_ike,
        'ipsec_hash': hsh_ipsec,
    }


def _assess_l2l_alg_status(alg_dict):
    """
    Assesses FTD compatibility of live L2L algorithms.
    Returns (overall_status, issues_list).
    issues_list: [ {'field', 'alg', 'status'} ]
    """
    issues = []
    all_statuses = []

    checks = [
        ('IKE Encryption',  alg_dict.get('ike_enc',    []), FTD_IKE_ENC),
        ('IKE Hash',        alg_dict.get('ike_hash',   []), FTD_IKE_HASH),
        ('IPsec Encryption',alg_dict.get('ipsec_enc',  []), FTD_ESP_ENC),
        ('IPsec Integrity', alg_dict.get('ipsec_hash', []), FTD_ESP_INT),
    ]

    for field, algs, table in checks:
        for alg in algs:
            status = _alg_status(alg, table)
            all_statuses.append(status)
            if status in ('REMOVED', 'DEPRECATED'):
                issues.append({
                    'field' : field,
                    'alg'   : alg,
                    'status': status,
                })

    return _worst_status(all_statuses), issues


def parse_vpn_l2l(lines):
    """
    Parses 'show vpn-sessiondb l2l' per-tunnel output.

    Returns list of dicts per tunnel:
      connection, index, ip, protocol,
      encryption_raw, hashing_raw,
      alg_detail (ike_enc, ipsec_enc, ike_hash, ipsec_hash),
      alg_status (REMOVED/DEPRECATED/OK),
      alg_issues (list),
      bytes_tx, bytes_rx, duration, login_time
    """
    tunnels = []
    current = None

    for line in lines:
        s = line.strip()
        if not s or re.match(r'^-+$', s):
            continue
        if s.lower().startswith('session type'):
            continue

        m = RE_L2L_CONNECTION.match(s)
        if m:
            current = {
                'connection'    : m.group(1),
                'index'         : None,
                'ip'            : m.group(1),
                'protocol'      : None,
                'encryption_raw': None,
                'hashing_raw'   : None,
                'alg_detail'    : {},
                'alg_status'    : 'UNKNOWN',
                'alg_issues'    : [],
                'bytes_tx'      : None,
                'bytes_rx'      : None,
                'duration'      : None,
                'login_time'    : None,
            }
            tunnels.append(current)
            continue

        if current is None:
            continue

        m = RE_L2L_INDEX.match(s)
        if m:
            current['index'] = m.group(1)

        m = RE_L2L_IP.match(s)
        if m:
            current['ip'] = m.group(1)

        m = RE_L2L_PROTOCOL.match(s)
        if m:
            current['protocol'] = m.group(1).strip()

        m = RE_L2L_ENCRYPTION.match(s)
        if m:
            current['encryption_raw'] = m.group(1).strip()

        m = RE_L2L_HASHING.match(s)
        if m:
            current['hashing_raw'] = m.group(1).strip()
            # Once we have both enc and hash, assess algorithms
            if current['encryption_raw']:
                current['alg_detail'] = _parse_l2l_algorithms(
                    current['encryption_raw'],
                    current['hashing_raw']
                )
                current['alg_status'], current['alg_issues'] = \
                    _assess_l2l_alg_status(current['alg_detail'])

        m = RE_L2L_BYTES_TX.search(s)
        if m:
            current['bytes_tx'] = int(m.group(1).replace(',', ''))

        m = RE_L2L_BYTES_RX.search(s)
        if m:
            current['bytes_rx'] = int(m.group(1).replace(',', ''))

        m = RE_L2L_DURATION.match(s)
        if m:
            current['duration'] = m.group(1).strip()

        m = RE_L2L_LOGIN.match(s)
        if m:
            current['login_time'] = m.group(1).strip()

    return tunnels


def print_vpn_l2l(tunnels):
    print("=" * 78)
    print("  ACTIVE L2L (SITE-TO-SITE) TUNNELS  (show vpn-sessiondb l2l)")
    print("=" * 78)

    if not tunnels:
        print("  [INFO] No active L2L tunnels at capture time.")
        print()
        return

    removed    = [t for t in tunnels if t['alg_status'] == 'REMOVED']
    deprecated = [t for t in tunnels if t['alg_status'] == 'DEPRECATED']
    clean      = [t for t in tunnels if t['alg_status'] == 'OK']

    print(f"\n  Active tunnels captured : {len(tunnels)}")
    print(f"  Algorithm status — REMOVED    : {len(removed)}")
    print(f"  Algorithm status — DEPRECATED : {len(deprecated)}")
    print(f"  Algorithm status — OK         : {len(clean)}")
    print()

    # REMOVED first, then DEPRECATED, then clean
    ordered = removed + deprecated + clean

    print(f"  {'PEER IP':<20} {'PROTOCOL':<16} {'STATUS':<12}"
          f" {'DURATION':<14} {'TX BYTES':>12} {'RX BYTES':>12}")
    print(f"  {'-'*19} {'-'*15} {'-'*11} {'-'*13} {'-'*12} {'-'*12}")

    for t in ordered:
        tx = f"{t['bytes_tx']:,}" if t['bytes_tx'] is not None else '—'
        rx = f"{t['bytes_rx']:,}" if t['bytes_rx'] is not None else '—'
        print(f"  {t['ip']:<20} {(t['protocol'] or '—'):<16} "
              f"{_flag(t['alg_status']):<12} "
              f"{(t['duration'] or '—'):<14} {tx:>12} {rx:>12}")

        if t['alg_issues']:
            for issue in t['alg_issues']:
                print(f"       [{issue['status']}] "
                      f"{issue['field']}: {issue['alg']}")

    if removed or deprecated:
        print()
        print("  [FLAG] Tunnels with REMOVED or DEPRECATED algorithms are")
        print("  negotiating with weak crypto RIGHT NOW. These peers must")
        print("  coordinate algorithm updates before FTD cutover or the")
        print("  tunnels will fail to re-establish post-migration.")
        print("  See Crypto Remediation Report for per-tunnel FMC actions.")
    print()


# ════════════════════════════════════════════════════════════
# PARSER 7: VPN-SESSIONDB-RATIO-ENC and RATIO-PROTO
# show vpn-sessiondb ratio encryption
# show vpn-sessiondb ratio protocol
# ════════════════════════════════════════════════════════════
# Expected format:
# Encryption used by all active sessions:
#    Algorithm  Count  Percentage
#    AES-256    125    95%
#    3DES       5      4%
#    DES        1      1%
#
# Protocol used by all active sessions:
#    Protocol   Count  Percentage
#    IKEv2      100    76%
#    IKEv1      25     19%
#    SSL        5      4%

RE_RATIO_ROW = re.compile(
    r'^(\S[\S\s]*?)\s{2,}(\d+)\s+([\d\.]+)%',
    re.IGNORECASE
)
RE_RATIO_TOTAL = re.compile(
    r'Total\s+(\d+)',
    re.IGNORECASE
)


def parse_vpn_ratio(lines):
    """
    Parses 'show vpn-sessiondb ratio encryption' or
    'show vpn-sessiondb ratio protocol' output.

    Returns list of dicts:
      label, count, percentage
    And totals dict: total_sessions
    """
    rows   = []
    totals = {'total_sessions': None}

    for line in lines:
        s = line.strip()
        if not s or s.lower().startswith(('algorithm', 'protocol',
                                          'encryption', 'used by')):
            continue

        m = RE_RATIO_TOTAL.search(s)
        if m and 'total' in s.lower():
            totals['total_sessions'] = int(m.group(1))
            continue

        m = RE_RATIO_ROW.match(s)
        if m:
            rows.append({
                'label'     : m.group(1).strip(),
                'count'     : int(m.group(2)),
                'percentage': float(m.group(3)),
            })

    return rows, totals


def print_vpn_ratio(rows, totals, section_name):
    label = ('Encryption' if 'ENC' in section_name.upper()
             else 'Protocol')
    print(f"  {'─'*60}")
    print(f"  VPN SESSION RATIO — {label.upper()}")
    print(f"  {'─'*60}")

    if not rows:
        print("  [INFO] No ratio data parsed.")
        print()
        return

    if totals.get('total_sessions'):
        print(f"  Total sessions: {totals['total_sessions']}")
    print()
    print(f"  {'ALGORITHM/PROTOCOL':<25} {'COUNT':>8} {'PERCENTAGE':>10}")
    print(f"  {'-'*24} {'-'*8} {'-'*10}")

    for r in sorted(rows, key=lambda x: -x['percentage']):
        status = ''
        if label == 'Encryption':
            st = _alg_status(r['label'], FTD_ESP_ENC)
            if st in ('REMOVED', 'DEPRECATED'):
                status = f"  {_flag(st)}"
        print(f"  {r['label']:<25} {r['count']:>8} "
              f"{r['percentage']:>9.1f}%{status}")

    # Flag any REMOVED encryption in active sessions
    if label == 'Encryption':
        removed_rows = [
            r for r in rows
            if _alg_status(r['label'], FTD_ESP_ENC) == 'REMOVED'
        ]
        if removed_rows:
            pct = sum(r['percentage'] for r in removed_rows)
            print()
            print(f"  [FLAG] {pct:.1f}% of active sessions use REMOVED")
            print("  encryption algorithms. These tunnels WILL FAIL to")
            print("  re-establish after migration without remediation.")
    print()


# ════════════════════════════════════════════════════════════
# PARSER 8: VPN-SESSIONDB-FULL / VPN-SESSIONDB-DETAIL
# show vpn-sessiondb full  (superset — detail feeds same parser)
# ════════════════════════════════════════════════════════════
# Full output includes all L2L and AnyConnect session detail.
# For migration purposes we focus on L2L entries since those
# map directly to S2S VPN config in FMC.
# Same field structure as L2L but may also include:
#   Group Policy, Tunnel Group, Auth Method

RE_FULL_TUNNEL_GROUP = re.compile(
    r'^Tunnel Group\s*:\s*(\S+)', re.IGNORECASE
)
RE_FULL_GROUP_POLICY = re.compile(
    r'^Group Policy\s*:\s*(\S+)', re.IGNORECASE
)
RE_FULL_AUTH = re.compile(
    r'^Auth Method\s*:\s*(.+)', re.IGNORECASE
)


def parse_vpn_full(lines):
    """
    Parses 'show vpn-sessiondb full' or 'show vpn-sessiondb detail'.
    Extracts all L2L session entries with algorithm detail.
    AnyConnect sessions are counted but not deeply parsed here.

    Returns:
      l2l_tunnels   : list of tunnel dicts (same structure as parse_vpn_l2l
                      plus tunnel_group, group_policy, auth_method)
      ac_count      : int  (AnyConnect session count)
    """
    l2l_tunnels = []
    ac_count    = 0
    current     = None
    in_l2l      = False

    for line in lines:
        s = line.strip()
        if not s or re.match(r'^-+$', s):
            continue

        # Detect session type block header
        if s.lower().startswith('session type:'):
            stype = s.lower()
            in_l2l = 'lan-to-lan' in stype or 'ipsec' in stype
            if 'anyconnect' in stype or 'ssl' in stype:
                ac_count += 1
                in_l2l = False
            current = None
            continue

        m = RE_L2L_CONNECTION.match(s)
        if m:
            current = {
                'connection'    : m.group(1),
                'index'         : None,
                'ip'            : m.group(1),
                'protocol'      : None,
                'encryption_raw': None,
                'hashing_raw'   : None,
                'alg_detail'    : {},
                'alg_status'    : 'UNKNOWN',
                'alg_issues'    : [],
                'bytes_tx'      : None,
                'bytes_rx'      : None,
                'duration'      : None,
                'login_time'    : None,
                'tunnel_group'  : None,
                'group_policy'  : None,
                'auth_method'   : None,
            }
            if in_l2l:
                l2l_tunnels.append(current)
            continue

        if current is None:
            continue

        # All the same fields as L2L
        for pattern, key in [
            (RE_L2L_INDEX,    'index'),
            (RE_L2L_DURATION, 'duration'),
            (RE_L2L_LOGIN,    'login_time'),
        ]:
            m = pattern.match(s)
            if m:
                current[key] = m.group(1).strip()

        m = RE_L2L_IP.match(s)
        if m:
            current['ip'] = m.group(1)

        m = RE_L2L_PROTOCOL.match(s)
        if m:
            current['protocol'] = m.group(1).strip()

        m = RE_L2L_ENCRYPTION.match(s)
        if m:
            current['encryption_raw'] = m.group(1).strip()

        m = RE_L2L_HASHING.match(s)
        if m:
            current['hashing_raw'] = m.group(1).strip()
            if current['encryption_raw']:
                current['alg_detail'] = _parse_l2l_algorithms(
                    current['encryption_raw'],
                    current['hashing_raw']
                )
                current['alg_status'], current['alg_issues'] = \
                    _assess_l2l_alg_status(current['alg_detail'])

        m = RE_L2L_BYTES_TX.search(s)
        if m:
            current['bytes_tx'] = int(m.group(1).replace(',', ''))

        m = RE_L2L_BYTES_RX.search(s)
        if m:
            current['bytes_rx'] = int(m.group(1).replace(',', ''))

        m = RE_FULL_TUNNEL_GROUP.match(s)
        if m:
            current['tunnel_group'] = m.group(1)

        m = RE_FULL_GROUP_POLICY.match(s)
        if m:
            current['group_policy'] = m.group(1)

        m = RE_FULL_AUTH.match(s)
        if m:
            current['auth_method'] = m.group(1).strip()

    return l2l_tunnels, ac_count


def print_vpn_full(l2l_tunnels, ac_count):
    print("=" * 78)
    print("  VPN FULL SESSION DETAIL  (show vpn-sessiondb full/detail)")
    print("=" * 78)

    if not l2l_tunnels and ac_count == 0:
        print("  [INFO] No session detail data parsed.")
        print()
        return

    removed    = [t for t in l2l_tunnels if t['alg_status'] == 'REMOVED']
    deprecated = [t for t in l2l_tunnels if t['alg_status'] == 'DEPRECATED']
    clean      = [t for t in l2l_tunnels if t['alg_status'] == 'OK']

    print(f"\n  L2L tunnels in full output : {len(l2l_tunnels)}")
    print(f"  AnyConnect sessions        : {ac_count}")
    print(f"\n  L2L Algorithm Status:")
    print(f"    REMOVED    : {len(removed)}")
    print(f"    DEPRECATED : {len(deprecated)}")
    print(f"    OK         : {len(clean)}")

    if removed or deprecated:
        print()
        print("  TUNNELS REQUIRING FMC ACTION:")
        print(f"  {'─'*74}")
        print(f"  {'PEER IP':<20} {'TUNNEL GROUP':<25} {'STATUS':<12}"
              f" {'PROTOCOL'}")
        print(f"  {'-'*19} {'-'*24} {'-'*11} {'-'*15}")

        for t in removed + deprecated:
            tg = t.get('tunnel_group') or '—'
            print(f"  {t['ip']:<20} {tg:<25} "
                  f"{_flag(t['alg_status']):<12} "
                  f"{t['protocol'] or '—'}")
            for issue in t['alg_issues']:
                print(f"       [{issue['status']}] "
                      f"{issue['field']}: {issue['alg']}")

        print()
        print("  These tunnels are CURRENTLY ACTIVE with weak algorithms.")
        print("  They will fail to re-establish after FTD cutover unless")
        print("  FMC config and peer crypto config are updated first.")

    print()


# ════════════════════════════════════════════════════════════
# PARSER 9: CRYPTO-ISAKMP-SA / CRYPTO-IKEv1-SA
# show crypto isakmp sa  /  show crypto ikev1 sa
# ════════════════════════════════════════════════════════════
# Two common output formats depending on ASA version:
#
# Older format (show crypto isakmp sa):
# dst             src             state          conn-id slot status
# 203.0.113.50    192.0.2.1       QM_IDLE          1234    0 ACTIVE
#
# Newer format (show crypto ikev1 sa):
# IKEv1 SAs:
#    Active SA: 1
#    Rekey SA: 0 (A tunnel will report 1 Active and 1 Rekey SA during rekey)
# Total IKE SA: 1
#
# 1   IKE Peer: 203.0.113.50
#     Type    : L2L             Role    : initiator
#     Rekey   : no              State   : MM_ACTIVE

RE_ISAKMP_SA_OLD = re.compile(
    r'^([\d\.]+)\s+([\d\.]+)\s+(\S+)\s+(\d+)\s+\d+\s+(\S+)',
    re.IGNORECASE
)
RE_IKEv1_PEER = re.compile(
    r'IKE Peer:\s*([\d\.]+)',
    re.IGNORECASE
)
RE_IKEv1_TYPE = re.compile(
    r'Type\s*:\s*(\S+)',
    re.IGNORECASE
)
RE_IKEv1_ROLE = re.compile(
    r'Role\s*:\s*(\S+)',
    re.IGNORECASE
)
RE_IKEv1_STATE = re.compile(
    r'State\s*:\s*(\S+)',
    re.IGNORECASE
)
RE_IKEv1_REKEY = re.compile(
    r'Rekey\s*:\s*(\S+)',
    re.IGNORECASE
)


def parse_isakmp_sa(lines):
    """
    Parses 'show crypto isakmp sa' or 'show crypto ikev1 sa' output.
    Handles both old columnar and newer block formats.

    Returns list of dicts:
      dst, src, state, conn_id, status (old format)
      OR
      peer, type, role, state, rekey (new format)
    """
    sas     = []
    current = None

    # Detect format by checking for 'IKE Peer:' pattern
    has_new_format = any(
        RE_IKEv1_PEER.search(l) for l in lines
    )

    if has_new_format:
        for line in lines:
            s = line.strip()
            m = RE_IKEv1_PEER.search(s)
            if m:
                current = {
                    'peer' : m.group(1),
                    'type' : None,
                    'role' : None,
                    'state': None,
                    'rekey': None,
                }
                sas.append(current)
                continue
            if current is None:
                continue
            for pat, key in [
                (RE_IKEv1_TYPE,  'type'),
                (RE_IKEv1_ROLE,  'role'),
                (RE_IKEv1_STATE, 'state'),
                (RE_IKEv1_REKEY, 'rekey'),
            ]:
                m2 = pat.search(s)
                if m2:
                    current[key] = m2.group(1)
    else:
        for line in lines:
            s = line.strip()
            if not s or s.startswith('dst') or s.startswith('---'):
                continue
            m = RE_ISAKMP_SA_OLD.match(s)
            if m:
                sas.append({
                    'peer'   : m.group(1),
                    'src'    : m.group(2),
                    'state'  : m.group(3),
                    'conn_id': m.group(4),
                    'status' : m.group(5),
                    'type'   : None,
                    'role'   : None,
                    'rekey'  : None,
                })

    return sas


def print_isakmp_sa(sas, label='IKEv1'):
    print(f"  {'─'*70}")
    print(f"  {label} PHASE 1 SAs (show crypto isakmp sa / ikev1 sa)")
    print(f"  {'─'*70}")

    if not sas:
        print(f"  [INFO] No active {label} Phase 1 SAs at capture time.")
        print()
        return

    print(f"\n  Active {label} SAs: {len(sas)}")
    print()
    print(f"  {'PEER IP':<22} {'STATE':<14} {'ROLE':<12} {'TYPE':<10} {'STATUS'}")
    print(f"  {'-'*21} {'-'*13} {'-'*11} {'-'*9} {'-'*10}")

    for sa in sas:
        peer   = sa.get('peer', '—')
        state  = sa.get('state', '—')
        role   = sa.get('role', '—')
        satype = sa.get('type', '—')
        status = sa.get('status', '—')
        print(f"  {peer:<22} {state:<14} {role:<12} {satype:<10} {status}")

    # Flag unhealthy states
    unhealthy = [
        sa for sa in sas
        if sa.get('state', '').upper() not in
        ('QM_IDLE', 'MM_ACTIVE', 'IKE_IDLE', 'ACTIVE', '')
    ]
    if unhealthy:
        print()
        print(f"  [FLAG] {len(unhealthy)} SA(s) in non-ACTIVE state:")
        for sa in unhealthy:
            print(f"    Peer {sa['peer']}: state={sa['state']}")
        print("  Investigate before cutover — unhealthy SAs may indicate")
        print("  negotiation failures that will persist post-migration.")
    print()


# ════════════════════════════════════════════════════════════
# PARSER 10: CRYPTO-IKEv2-SA
# show crypto ikev2 sa
# ════════════════════════════════════════════════════════════
# Expected format:
# IKEv2 SAs:
#
# Session-id:1, Status:UP-ACTIVE, IKE count:1, CHILD count:1
#
# Tunnel-id Local                 Remote                fvrf/ivrf            Status
# 1         192.0.2.1/500         203.0.113.50/500       none/none            READY
#       Encr: AES-CBC, keysize: 256, PRF: SHA384, Hash: SHA384,
#       DH Grp: 20, Auth sign: PSK, Auth verify: PSK
#       Life/Active Time: 86400/9000 sec

RE_IKEv2_SESSION = re.compile(
    r'Session-id\s*:\s*(\d+).*?Status\s*:\s*(\S+)',
    re.IGNORECASE
)
RE_IKEv2_TUNNEL = re.compile(
    r'^(\d+)\s+([\d\.\:]+/\d+)\s+([\d\.\:]+/\d+)',
    re.IGNORECASE
)
RE_IKEv2_ENCR = re.compile(
    r'Encr\s*:\s*(\S+(?:-\S+)*)',
    re.IGNORECASE
)
RE_IKEv2_KEYSIZE = re.compile(
    r'keysize\s*:\s*(\d+)',
    re.IGNORECASE
)
RE_IKEv2_PRF = re.compile(
    r'PRF\s*:\s*(\S+)',
    re.IGNORECASE
)
RE_IKEv2_HASH = re.compile(
    r'Hash\s*:\s*(\S+)',
    re.IGNORECASE
)
RE_IKEv2_DH = re.compile(
    r'DH Grp\s*:\s*(\d+)',
    re.IGNORECASE
)
RE_IKEv2_AUTH = re.compile(
    r'Auth sign\s*:\s*(\S+)',
    re.IGNORECASE
)
RE_IKEv2_LIFETIME = re.compile(
    r'Life/Active Time\s*:\s*(\d+)/(\d+)',
    re.IGNORECASE
)


def parse_ikev2_sa(lines):
    """
    Parses 'show crypto ikev2 sa' output.

    Returns list of dicts per tunnel:
      session_id, status, local, remote,
      encryption, keysize, prf, hash_alg, dh_group, auth,
      lifetime, active_time,
      alg_status (REMOVED/DEPRECATED/OK),
      alg_issues (list)
    """
    sas     = []
    current = None

    for line in lines:
        s = line.strip()
        if not s or re.match(r'^-+$', s):
            continue

        m = RE_IKEv2_SESSION.search(s)
        if m:
            current = {
                'session_id' : m.group(1),
                'status'     : m.group(2),
                'local'      : None,
                'remote'     : None,
                'encryption' : None,
                'keysize'    : None,
                'prf'        : None,
                'hash_alg'   : None,
                'dh_group'   : None,
                'auth'       : None,
                'lifetime'   : None,
                'active_time': None,
                'alg_status' : 'UNKNOWN',
                'alg_issues' : [],
            }
            sas.append(current)
            continue

        if current is None:
            continue

        m = RE_IKEv2_TUNNEL.match(s)
        if m:
            current['local']  = m.group(2)
            current['remote'] = m.group(3)
            continue

        m = RE_IKEv2_ENCR.search(s)
        if m:
            current['encryption'] = m.group(1)

        m = RE_IKEv2_KEYSIZE.search(s)
        if m:
            current['keysize'] = m.group(1)

        m = RE_IKEv2_PRF.search(s)
        if m:
            current['prf'] = m.group(1)

        m = RE_IKEv2_HASH.search(s)
        if m:
            current['hash_alg'] = m.group(1)

        m = RE_IKEv2_DH.search(s)
        if m:
            current['dh_group'] = m.group(1)

        m = RE_IKEv2_AUTH.search(s)
        if m:
            current['auth'] = m.group(1)

        m = RE_IKEv2_LIFETIME.search(s)
        if m:
            current['lifetime']    = m.group(1)
            current['active_time'] = m.group(2)

        # Assess algorithms once we have encryption
        if current['encryption']:
            enc_alg = current['encryption'].lower()
            if current['keysize']:
                enc_alg = f"aes-{current['keysize']}"

            issues = []
            statuses = []

            for alg, table, label in [
                (enc_alg,                    FTD_IKE_ENC,  'IKE Encryption'),
                (current['hash_alg'] or '',  FTD_IKE_HASH, 'IKE Hash'),
                (current['prf'] or '',       FTD_IKE_HASH, 'PRF'),
            ]:
                if alg:
                    st = _alg_status(alg, table)
                    statuses.append(st)
                    if st in ('REMOVED', 'DEPRECATED'):
                        issues.append({'field': label, 'alg': alg, 'status': st})

            if current['dh_group']:
                from collections import OrderedDict
                dh_st = FTD_DH.get(current['dh_group'], 'UNKNOWN')
                statuses.append(dh_st)
                if dh_st in ('REMOVED', 'DEPRECATED'):
                    issues.append({
                        'field' : 'DH Group',
                        'alg'   : f"group {current['dh_group']}",
                        'status': dh_st,
                    })

            current['alg_status'] = _worst_status(statuses)
            current['alg_issues'] = issues

    return sas


def print_ikev2_sa(sas):
    print(f"  {'─'*70}")
    print(f"  IKEv2 PHASE 1 SAs  (show crypto ikev2 sa)")
    print(f"  {'─'*70}")

    if not sas:
        print("  [INFO] No active IKEv2 Phase 1 SAs at capture time.")
        print()
        return

    removed    = [s for s in sas if s['alg_status'] == 'REMOVED']
    deprecated = [s for s in sas if s['alg_status'] == 'DEPRECATED']

    print(f"\n  Active IKEv2 SAs : {len(sas)}")
    print(f"  REMOVED          : {len(removed)}")
    print(f"  DEPRECATED       : {len(deprecated)}")
    print()

    print(f"  {'REMOTE':<24} {'ENC':<12} {'KEYSIZE':<9} "
          f"{'HASH':<10} {'DH':>5} {'STATUS':<12} {'UPTIME'}")
    print(f"  {'-'*23} {'-'*11} {'-'*8} {'-'*9} {'-'*5}"
          f" {'-'*11} {'-'*10}")

    for sa in sas:
        remote  = (sa['remote'] or '—').split('/')[0]
        enc     = sa['encryption'] or '—'
        ks      = sa['keysize'] or '—'
        hsh     = sa['hash_alg'] or '—'
        dh      = sa['dh_group'] or '—'
        uptime  = sa['active_time'] or '—'
        print(f"  {remote:<24} {enc:<12} {ks:<9} "
              f"{hsh:<10} {dh:>5} "
              f"{_flag(sa['alg_status']):<12} {uptime}s")

        for issue in sa['alg_issues']:
            print(f"       [{issue['status']}] "
                  f"{issue['field']}: {issue['alg']}")
    print()


# ════════════════════════════════════════════════════════════
# PARSER 11: CRYPTO-IPSEC-SA (deeper)
# show crypto ipsec sa
# ════════════════════════════════════════════════════════════
# Per-peer block format:
# interface: outside
#     Crypto map tag: outside_map, seq num: 10, local addr: 192.0.2.1
#
#       local  ident (addr/mask/prot/port): (10.1.0.0/255.255.0.0/0/0)
#       remote ident (addr/mask/prot/port): (10.2.0.0/255.255.0.0/0/0)
#       current_peer: 203.0.113.50
#
#      #pkts encaps: 12345, #pkts encrypt: 12345, #pkts digest: 12345
#      #pkts decaps: 12345, #pkts decrypt: 12345, #pkts verify: 12345
#      #pkts compressed: 0, #pkts decompressed: 0
#      #pkts not compressed: 0, #pkts compr. failed: 0
#      #pkts not decompressed: 0, #pkts decompress failed: 0
#      #send errors: 0, #recv errors: 0
#
#      local crypto endpt.: 192.0.2.1, remote crypto endpt.: 203.0.113.50
#      path mtu 1500, ip mtu 1500, ip mtu idb outside
#      current outbound spi: 0xABCD1234 (1234567)
#      current inbound spi : 0x12345678 (305419896)
#
#     inbound esp sas:
#      spi: 0x12345678 (305419896)
#        transform-set: ESP-AES256-SHA256
#        in use settings ={L2L, Tunnel, IKEv2, }
#        conn id: 1234, flow_id: 1, sibling_flags 0x00, crypto map: outside_map
#        sa timing: remaining key lifetime (kB/sec): (4608000/3582)
#        IV size: 16 bytes
#        replay detection support: Y
#        Status: ACTIVE(ACTIVE)
#
#     outbound esp sas:
#      spi: 0xABCD1234 (1234567)
#        transform-set: ESP-AES256-SHA256
#        in use settings ={L2L, Tunnel, IKEv2, }

RE_IPSEC_IFACE      = re.compile(r'^interface:\s*(\S+)', re.IGNORECASE)
RE_IPSEC_CRYPTO_MAP = re.compile(
    r'Crypto map tag:\s*(\S+),\s*seq num:\s*(\d+)', re.IGNORECASE
)
RE_IPSEC_LOCAL_ADDR = re.compile(
    r'local addr:\s*([\d\.]+)', re.IGNORECASE
)
RE_IPSEC_PEER       = re.compile(
    r'current_peer:\s*([\d\.]+)', re.IGNORECASE
)
RE_IPSEC_LOCAL_ID   = re.compile(
    r'local\s+ident.*?:\s*\(([^\)]+)\)', re.IGNORECASE
)
RE_IPSEC_REMOTE_ID  = re.compile(
    r'remote\s+ident.*?:\s*\(([^\)]+)\)', re.IGNORECASE
)
RE_IPSEC_ENCAPS     = re.compile(
    r'#pkts encaps:\s*(\d+)', re.IGNORECASE
)
RE_IPSEC_DECAPS     = re.compile(
    r'#pkts decaps:\s*(\d+)', re.IGNORECASE
)
RE_IPSEC_SEND_ERR   = re.compile(
    r'#send errors:\s*(\d+)', re.IGNORECASE
)
RE_IPSEC_RECV_ERR   = re.compile(
    r'#recv errors:\s*(\d+)', re.IGNORECASE
)
RE_IPSEC_TRANSFORM  = re.compile(
    r'transform-set:\s*(\S+)', re.IGNORECASE
)
RE_IPSEC_SPI_IN     = re.compile(
    r'inbound esp sas:', re.IGNORECASE
)
RE_IPSEC_SPI_OUT    = re.compile(
    r'outbound esp sas:', re.IGNORECASE
)
RE_IPSEC_SA_STATUS  = re.compile(
    r'Status:\s*(\S+)', re.IGNORECASE
)
RE_IPSEC_SETTINGS   = re.compile(
    r'in use settings\s*=\s*\{([^\}]+)\}', re.IGNORECASE
)
RE_IPSEC_LIFETIME   = re.compile(
    r'remaining key lifetime.*?:\s*\((\d+)/(\d+)\)', re.IGNORECASE
)


def parse_ipsec_sa(lines):
    """
    Parses 'show crypto ipsec sa' output.

    Returns list of dicts per SA pair (inbound + outbound):
      interface, crypto_map, map_seq, local_addr, peer,
      local_ident, remote_ident,
      transform_set, settings, sa_status,
      encaps, decaps, send_errors, recv_errors,
      lifetime_kb, lifetime_sec,
      alg_status, alg_issues
    """
    sas          = []
    current_iface = None
    current_map   = None
    current_seq   = None
    current_local = None
    current       = None
    in_inbound    = False

    for line in lines:
        s = line.strip()
        if not s:
            continue

        m = RE_IPSEC_IFACE.match(s)
        if m:
            current_iface = m.group(1)
            continue

        m = RE_IPSEC_CRYPTO_MAP.search(s)
        if m:
            current_map = m.group(1)
            current_seq = m.group(2)
            current     = None

        m = RE_IPSEC_LOCAL_ADDR.search(s)
        if m:
            current_local = m.group(1)

        m = RE_IPSEC_PEER.search(s)
        if m:
            current = {
                'interface'   : current_iface,
                'crypto_map'  : current_map,
                'map_seq'     : current_seq,
                'local_addr'  : current_local,
                'peer'        : m.group(1),
                'local_ident' : None,
                'remote_ident': None,
                'transform_set': None,
                'settings'    : None,
                'sa_status'   : None,
                'encaps'      : None,
                'decaps'      : None,
                'send_errors' : None,
                'recv_errors' : None,
                'lifetime_kb' : None,
                'lifetime_sec': None,
                'alg_status'  : 'UNKNOWN',
                'alg_issues'  : [],
            }
            sas.append(current)
            in_inbound = False
            continue

        if current is None:
            continue

        m = RE_IPSEC_LOCAL_ID.search(s)
        if m:
            current['local_ident'] = m.group(1)

        m = RE_IPSEC_REMOTE_ID.search(s)
        if m:
            current['remote_ident'] = m.group(1)

        m = RE_IPSEC_ENCAPS.search(s)
        if m:
            current['encaps'] = int(m.group(1))

        m = RE_IPSEC_DECAPS.search(s)
        if m:
            current['decaps'] = int(m.group(1))

        m = RE_IPSEC_SEND_ERR.search(s)
        if m:
            current['send_errors'] = int(m.group(1))

        m = RE_IPSEC_RECV_ERR.search(s)
        if m:
            current['recv_errors'] = int(m.group(1))

        if RE_IPSEC_SPI_IN.search(s):
            in_inbound = True

        if RE_IPSEC_SPI_OUT.search(s):
            in_inbound = False

        # Only capture transform-set from inbound SAs
        if in_inbound:
            m = RE_IPSEC_TRANSFORM.search(s)
            if m and not current['transform_set']:
                ts_name = m.group(1)
                current['transform_set'] = ts_name
                # Assess the transform set name against known weak patterns
                ts_lower = ts_name.lower()
                issues   = []
                statuses = []

                for alg, table, label in [
                    ('3des',         FTD_ESP_ENC,  'IPsec Encryption'),
                    ('des',          FTD_ESP_ENC,  'IPsec Encryption'),
                    ('md5',          FTD_ESP_INT,  'IPsec Integrity'),
                    ('esp-3des',     FTD_ESP_ENC,  'IPsec Encryption'),
                    ('esp-des',      FTD_ESP_ENC,  'IPsec Encryption'),
                    ('esp-md5-hmac', FTD_ESP_INT,  'IPsec Integrity'),
                    ('sha-hmac',     FTD_ESP_INT,  'IPsec Integrity'),
                    ('sha256',       FTD_ESP_INT,  'IPsec Integrity'),
                ]:
                    if alg in ts_lower:
                        st = _alg_status(alg, table)
                        statuses.append(st)
                        if st in ('REMOVED', 'DEPRECATED'):
                            issues.append({
                                'field' : label,
                                'alg'   : alg,
                                'status': st,
                            })

                current['alg_status'] = _worst_status(statuses) \
                    if statuses else 'OK'
                current['alg_issues'] = issues

            m = RE_IPSEC_SETTINGS.search(s)
            if m:
                current['settings'] = m.group(1).strip()

            m = RE_IPSEC_SA_STATUS.search(s)
            if m:
                current['sa_status'] = m.group(1)

            m = RE_IPSEC_LIFETIME.search(s)
            if m:
                current['lifetime_kb']  = m.group(1)
                current['lifetime_sec'] = m.group(2)

    return sas


def print_ipsec_sa(sas):
    print("=" * 78)
    print("  IPSEC PHASE 2 SAs  (show crypto ipsec sa)")
    print("=" * 78)

    if not sas:
        print("  [INFO] No IPsec SAs parsed. Tunnels may be down.")
        print()
        return

    removed    = [s for s in sas if s['alg_status'] == 'REMOVED']
    deprecated = [s for s in sas if s['alg_status'] == 'DEPRECATED']
    errored    = [
        s for s in sas
        if (s['send_errors'] or 0) > 0
        or (s['recv_errors'] or 0) > 0
    ]
    inactive   = [
        s for s in sas
        if s['sa_status'] and 'active' not in s['sa_status'].lower()
    ]

    print(f"\n  Total IPsec SAs    : {len(sas)}")
    print(f"  REMOVED algorithms : {len(removed)}")
    print(f"  DEPRECATED         : {len(deprecated)}")
    print(f"  SA errors present  : {len(errored)}")
    print(f"  Non-ACTIVE SAs     : {len(inactive)}")
    print()

    print(f"  {'PEER':<20} {'MAP':<20} {'SEQ':>5} "
          f"{'TRANSFORM SET':<25} {'STATUS':<12} {'ENCAPS':>10}")
    print(f"  {'-'*19} {'-'*19} {'-'*5} "
          f"{'-'*24} {'-'*11} {'-'*10}")

    for sa in sas:
        encaps = f"{sa['encaps']:,}" if sa['encaps'] is not None else '—'
        ts     = sa['transform_set'] or '—'
        mp     = sa['crypto_map']    or '—'
        seq    = sa['map_seq']       or '—'
        print(f"  {sa['peer']:<20} {mp:<20} {seq:>5} "
              f"{ts:<25} "
              f"{_flag(sa['alg_status']):<12} {encaps:>10}")

        for issue in sa['alg_issues']:
            print(f"       [{issue['status']}] "
                  f"{issue['field']}: {issue['alg']}")

    if removed:
        print()
        print("  [CRITICAL] IPsec SAs using REMOVED algorithms detected.")
        print("  These are active tunnels currently encapsulating traffic")
        print("  with algorithms that FTD does not support. They will NOT")
        print("  re-establish after migration without config remediation.")

    if errored:
        print()
        print(f"  [FLAG] {len(errored)} SA(s) with send/recv errors:")
        for sa in errored:
            print(f"    Peer {sa['peer']}: "
                  f"send_err={sa['send_errors']} "
                  f"recv_err={sa['recv_errors']}")
    print()


# ════════════════════════════════════════════════════════════
# PARSER 12: CRYPTO-IPSEC-STATS
# show crypto ipsec policy stats
# ════════════════════════════════════════════════════════════
# Expected format (aggregate counters):
# Global IPsec statistics:
# Active tunnels: 131
# Previous tunnels: 15230
# Inbound:
#   Bytes: 1234567890
#   Decompressed bytes: 0
#   Packets: 9876543
#   Dropped packets: 0
#   Replay failures: 0
#   Authentications: 9876543
#   Authentication failures: 0
#   Decryptions: 9876543
#   Decryption failures: 0
# Outbound:
#   Bytes: 987654321
#   Packets: 8765432
#   Dropped packets: 0
#   Authentications: 8765432
#   Authentication failures: 0
#   Encryptions: 8765432
#   Encryption failures: 0

RE_STATS_KV = re.compile(
    r'^([\w\s/]+?)\s*:\s*(\d+)',
    re.IGNORECASE
)


def parse_crypto_stats(lines, label='IPsec'):
    """
    Parses 'show crypto ipsec policy stats' or
    'show crypto isakmp stats' output.
    Extracts all key:value counter pairs.

    Returns dict of { counter_name: int_value }
    """
    stats   = {}
    section = 'global'

    for line in lines:
        s = line.strip()
        if not s:
            continue

        if s.lower().startswith('inbound'):
            section = 'inbound'
            continue
        if s.lower().startswith('outbound'):
            section = 'outbound'
            continue

        m = RE_STATS_KV.match(s)
        if m:
            key = f"{section}.{m.group(1).strip().lower().replace(' ', '_')}"
            stats[key] = int(m.group(2))

    return stats


def print_crypto_stats(stats, label='IPsec'):
    print(f"  {'─'*70}")
    print(f"  {label.upper()} STATISTICS")
    print(f"  {'─'*70}")

    if not stats:
        print(f"  [INFO] No {label} statistics parsed.")
        print()
        return

    # Highlight failure counters
    failure_keys = [k for k in stats if 'fail' in k or 'error' in k
                    or 'drop' in k or 'replay' in k]
    normal_keys  = [k for k in stats if k not in failure_keys]

    for key in sorted(normal_keys):
        short_key = key.split('.')[-1].replace('_', ' ').title()
        section   = key.split('.')[0].upper()
        print(f"  {section:<10} {short_key:<40} : {stats[key]:>12,}")

    if failure_keys:
        non_zero_failures = {k: v for k, v in stats.items()
                             if k in failure_keys and v > 0}
        if non_zero_failures:
            print()
            print(f"  [FLAG] Non-zero failure/error counters:")
            for k, v in sorted(non_zero_failures.items()):
                short_key = k.split('.')[-1].replace('_', ' ').title()
                section   = k.split('.')[0].upper()
                print(f"  {section:<10} {short_key:<40} : {v:>12,}")
            print("  Investigate these before cutover.")
        else:
            print()
            print(f"  [OK] All {label} failure counters are zero.")
    print()


# ════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════

def print_header():
    print()
    print("=" * 78)
    print("  ASA MIGRATION PARSER — PHASE 3")
    print("  Interface | Route | VPN Sessions | Live Crypto SA State")
    print("=" * 78)
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
    sections_data = extract_sections(filepath)

    def run(section, parser_fn, print_fn, *extra_args, label=None):
        lines = sections_data.get(section, [])
        if lines:
            result = parser_fn(lines)
            if isinstance(result, tuple):
                print_fn(*result, *extra_args)
            else:
                print_fn(result, *extra_args)
        else:
            name = label or section
            print(f"  [SKIPPED] {name} — section empty or not found.\n")

    # ── Interface parsers ──────────────────────────────────────
    run("INTERFACE-IP-BRIEF", parse_interface_brief, print_interface_brief)
    run("INTERFACE",          parse_interface_verbose, print_interface_verbose)

    # ── Route ──────────────────────────────────────────────────
    run("ROUTE", parse_route_table, print_route_table)

    # ── VPN session parsers ────────────────────────────────────
    run("VPN-SESSIONDB-SUMMARY",    parse_vpn_summary,    print_vpn_summary)
    run("VPN-SESSIONDB-ANYCONNECT", parse_vpn_anyconnect, print_vpn_anyconnect)
    run("VPN-SESSIONDB-L2L",        parse_vpn_l2l,        print_vpn_l2l)

    enc_lines   = sections_data.get("VPN-SESSIONDB-RATIO-ENC", [])
    proto_lines = sections_data.get("VPN-SESSIONDB-RATIO-PROTO", [])

    if enc_lines:
        rows, totals = parse_vpn_ratio(enc_lines)
        print_vpn_ratio(rows, totals, "VPN-SESSIONDB-RATIO-ENC")
    else:
        print("  [SKIPPED] VPN-SESSIONDB-RATIO-ENC — section empty or not found.\n")

    if proto_lines:
        rows, totals = parse_vpn_ratio(proto_lines)
        print_vpn_ratio(rows, totals, "VPN-SESSIONDB-RATIO-PROTO")
    else:
        print("  [SKIPPED] VPN-SESSIONDB-RATIO-PROTO — section empty or not found.\n")

    # VPN-SESSIONDB-FULL and DETAIL feed the same parser
    full_lines   = sections_data.get("VPN-SESSIONDB-FULL", [])
    detail_lines = sections_data.get("VPN-SESSIONDB-DETAIL", [])
    combined_full = full_lines or detail_lines
    if combined_full:
        l2l_tunnels, ac_count = parse_vpn_full(combined_full)
        print_vpn_full(l2l_tunnels, ac_count)
    else:
        print("  [SKIPPED] VPN-SESSIONDB-FULL/DETAIL — section empty or not found.\n")

    # ── Crypto SA parsers ──────────────────────────────────────
    # IKEv1 — try ikev1 sa first, fall back to isakmp sa
    ikev1_lines  = sections_data.get("CRYPTO-IKEv1-SA", [])
    isakmp_lines = sections_data.get("CRYPTO-ISAKMP-SA", [])
    ikev1_src    = ikev1_lines or isakmp_lines
    if ikev1_src:
        sas = parse_isakmp_sa(ikev1_src)
        print_isakmp_sa(sas, label='IKEv1')
    else:
        print("  [SKIPPED] CRYPTO-IKEv1-SA / CRYPTO-ISAKMP-SA — not found.\n")

    ikev2_lines = sections_data.get("CRYPTO-IKEv2-SA", [])
    if ikev2_lines:
        sas = parse_ikev2_sa(ikev2_lines)
        print_ikev2_sa(sas)
    else:
        print("  [SKIPPED] CRYPTO-IKEv2-SA — section empty or not found.\n")

    ipsec_sa_lines = sections_data.get("CRYPTO-IPSEC-SA", [])
    if ipsec_sa_lines:
        sas = parse_ipsec_sa(ipsec_sa_lines)
        print_ipsec_sa(sas)
    else:
        print("  [SKIPPED] CRYPTO-IPSEC-SA — section empty or not found.\n")

    ipsec_stats_lines  = sections_data.get("CRYPTO-IPSEC-STATS", [])
    isakmp_stats_lines = sections_data.get("CRYPTO-ISAKMP-STATS", [])

    if ipsec_stats_lines:
        stats = parse_crypto_stats(ipsec_stats_lines, 'IPsec')
        print_crypto_stats(stats, 'IPsec')
    else:
        print("  [SKIPPED] CRYPTO-IPSEC-STATS — section empty or not found.\n")

    if isakmp_stats_lines:
        stats = parse_crypto_stats(isakmp_stats_lines, 'ISAKMP')
        print_crypto_stats(stats, 'ISAKMP')
    else:
        print("  [SKIPPED] CRYPTO-ISAKMP-STATS — section empty or not found.\n")


if __name__ == "__main__":
    main()
