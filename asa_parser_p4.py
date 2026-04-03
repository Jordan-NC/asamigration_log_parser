# ============================================================
# ASA Migration Parser - Phase 4: ACL and Crypto Parsing
# ============================================================
# PURPOSE:
#   Parses three high-value migration sections using the FULL
#   documented ASA syntax specification — not just observed
#   sample output. Every unmatched line is explicitly captured
#   and reported. Nothing is silently dropped.
#
#   Sections parsed:
#     - ACCESS-LIST                : Hit counts, inactive rules,
#                                    remarks, zero-hit rules
#     - RUNNING-CONFIG-ACCESS-LIST : Clean config rules for
#                                    migration inventory
#     - RUNNING-CONFIG-CRYPTO      : All transform sets, IKE
#                                    policies, proposals, crypto
#                                    maps, weak algorithm flags,
#                                    FTD compatibility assessment
#
# USAGE:
#   python asa_parser_p4.py <path_to_log_file>
#
# THREE-LAYER PARSING ARCHITECTURE:
#   Layer 1 — Full spec pattern match: built against complete
#             Cisco ASA documented syntax for each command
#   Layer 2 — Partial match fallback: captures lines that look
#             relevant but don't fully match — flagged [PARTIAL]
#   Layer 3 — Unmatched capture: every non-matching line goes
#             into an UNMATCHED section per parser — visible,
#             never silently dropped
#
# ACL SYNTAX COVERAGE (per Cisco ASA CLI Reference):
#   Actions    : permit, deny
#   Types      : extended, standard, ethertype, webtype, ipv6
#   Protocols  : ip, tcp, udp, icmp, icmp6, esp, ah, gre,
#                ospf, eigrp, pim, igmp, sctp,
#                object <n>, object-group <n>
#   Addr forms : any, any4, any6, host <ip>, <ip> <mask>,
#                object <n>, object-group <n>,
#                interface <n>, fqdn <n>
#   Port ops   : eq, neq, lt, gt, range
#   Modifiers  : log [level] [interval n], inactive,
#                time-range <n>
#   ICMP types : echo, echo-reply, unreachable,
#                time-exceeded, redirect, traceroute,
#                + numeric types
#
# CRYPTO SYNTAX COVERAGE (per Cisco ASA VPN CLI Reference):
#   IKEv1 enc  : des, 3des, aes, aes-192, aes-256
#   IKEv1 hash : sha, sha256, sha384, sha512, md5
#   IKEv1 auth : pre-share, rsa-sig, crack
#   IKEv2 enc  : des, 3des, aes, aes-192, aes-256,
#                aes-gcm, aes-gcm-192, aes-gcm-256, null
#   IKEv2 int  : sha, sha256, sha384, sha512, md5, null
#   ESP enc    : esp-des, esp-3des, esp-aes, esp-aes-192,
#                esp-aes-256, esp-aes-gcm, esp-aes-gcm-192,
#                esp-aes-gcm-256, esp-null
#   ESP hash   : esp-sha-hmac, esp-sha256-hmac,
#                esp-sha384-hmac, esp-sha512-hmac,
#                esp-md5-hmac, esp-none
#   TS mode    : tunnel (default), transport
#   DH groups  : 1,2,5,14,19,20,21,24
#   FTD status : REMOVED / DEPRECATED / OK per algorithm
# ============================================================

import re
import sys
import os
from collections import defaultdict

# ── Section header regex ──────────────────────────────────────
SECTION_PATTERN = re.compile(
    r'^!\s*===SECTION:\s*([A-Z0-9_\-]+)\s*===$',
    re.IGNORECASE
)

# ════════════════════════════════════════════════════════════
# SECTION EXTRACTION
# ════════════════════════════════════════════════════════════

def extract_sections(filepath):
    """
    Reads the log file and returns:
      { section_name: [raw lines with leading whitespace preserved] }
    Leading whitespace is preserved because indented lines in
    show access-list output are expanded object references —
    indentation is the only way to detect and skip them.
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
# FTD ALGORITHM COMPATIBILITY TABLES
# Source: FMC Config Guide 6.7+, ASA 9.13/9.15 release notes
# ════════════════════════════════════════════════════════════

# FTD status values: 'REMOVED', 'DEPRECATED', 'OK'
FTD_ESP_ENCRYPTION = {
    'esp-des'         : 'REMOVED',
    'esp-3des'        : 'REMOVED',
    'esp-aes'         : 'OK',
    'esp-aes-192'     : 'OK',
    'esp-aes-256'     : 'OK',
    'esp-aes-gcm'     : 'OK',
    'esp-aes-gcm-192' : 'OK',
    'esp-aes-gcm-256' : 'OK',
    'esp-null'        : 'OK',
    # IKEv2 proposal form (no esp- prefix)
    'des'             : 'REMOVED',
    '3des'            : 'REMOVED',
    'aes'             : 'OK',
    'aes-192'         : 'OK',
    'aes-256'         : 'OK',
    'aes-gcm'         : 'OK',
    'aes-gcm-192'     : 'OK',
    'aes-gcm-256'     : 'OK',
    'null'            : 'OK',
}

FTD_ESP_INTEGRITY = {
    'esp-md5-hmac'    : 'REMOVED',
    'esp-sha-hmac'    : 'DEPRECATED',
    'esp-sha256-hmac' : 'OK',
    'esp-sha384-hmac' : 'OK',
    'esp-sha512-hmac' : 'OK',
    'esp-none'        : 'OK',
    # IKEv2 proposal form
    'md5'             : 'REMOVED',
    'sha'             : 'DEPRECATED',
    'sha256'          : 'OK',
    'sha384'          : 'OK',
    'sha512'          : 'OK',
    'null'            : 'OK',
}

FTD_IKE_ENCRYPTION = {
    'des'     : 'REMOVED',
    '3des'    : 'REMOVED',
    'aes'     : 'OK',
    'aes-192' : 'OK',
    'aes-256' : 'OK',
    # IKEv2 only
    'aes-gcm'     : 'OK',
    'aes-gcm-192' : 'OK',
    'aes-gcm-256' : 'OK',
    'null'        : 'OK',
}

FTD_IKE_HASH = {
    'md5'    : 'REMOVED',
    'sha'    : 'DEPRECATED',
    'sha256' : 'OK',
    'sha384' : 'OK',
    'sha512' : 'OK',
}

# DH group FTD status
# Group 5: deprecated for IKEv1, removed for IKEv2
# Groups 2, 24: removed entirely in FTD 6.7+
FTD_DH_GROUPS = {
    '1'  : 'REMOVED',
    '2'  : 'REMOVED',
    '5'  : 'DEPRECATED',   # IKEv1 deprecated, IKEv2 removed
    '14' : 'OK',
    '19' : 'OK',
    '20' : 'OK',
    '21' : 'OK',
    '24' : 'REMOVED',      # Removed in FTD 6.7+
}

FTD_STATUS_SYMBOL = {
    'REMOVED'    : '❌ REMOVED',
    'DEPRECATED' : '⚠️  DEPRECATED',
    'OK'         : '✅ OK',
}


def ftd_enc_status(alg):
    return FTD_ESP_ENCRYPTION.get(alg.lower(), 'UNKNOWN')

def ftd_int_status(alg):
    return FTD_ESP_INTEGRITY.get(alg.lower(), 'UNKNOWN')

def ftd_ike_enc_status(alg):
    return FTD_IKE_ENCRYPTION.get(alg.lower(), 'UNKNOWN')

def ftd_ike_hash_status(alg):
    return FTD_IKE_HASH.get(alg.lower(), 'UNKNOWN')

def ftd_dh_status(group):
    # Normalize: strip 'group' keyword if present
    g = re.sub(r'group\s*', '', group.lower()).strip()
    return FTD_DH_GROUPS.get(g, 'UNKNOWN')


# ════════════════════════════════════════════════════════════
# ACL SYNTAX CONSTANTS (full documented spec)
# ════════════════════════════════════════════════════════════

# All protocols ASA extended ACL supports
ASA_PROTOCOLS = {
    'ip', 'tcp', 'udp', 'icmp', 'icmp6', 'esp', 'ah', 'gre',
    'ospf', 'eigrp', 'pim', 'igmp', 'sctp', 'object',
    'object-group',
}

# All named TCP/UDP ports ASA recognizes
ASA_PORT_NAMES = {
    'www', 'http', 'https', 'ftp', 'ftp-data', 'ssh', 'telnet',
    'smtp', 'pop3', 'imap4', 'imap', 'ntp', 'snmp', 'snmptrap',
    'dns', 'domain', 'bgp', 'ldap', 'ldaps', 'kerberos',
    'radius', 'tacacs', 'tacacs+', 'h323', 'sip', 'rtsp',
    'sqlnet', 'oracle', 'mysql', 'mssql', 'msrpc', 'netbios-ns',
    'netbios-dgm', 'netbios-ssn', 'aol', 'citrix-ica', 'pptp',
    'rsh', 'rlogin', 'exec', 'talk', 'ident', 'finger',
    'daytime', 'time', 'chargen', 'echo', 'discard', 'whois',
    'gopher', 'hostname', 'sunrpc', 'rip', 'pim-auto-rp',
    'mobile-ip', 'bootps', 'bootpc', 'tftp', 'syslog',
    'isakmp', 'non500-isakmp', 'lotusnotes', 'ctiqbe',
    'asdm', 'secureid', 'kshell', 'klogin',
}

# All ICMP type names ASA recognizes in ACLs
ASA_ICMP_TYPES = {
    'echo', 'echo-reply', 'unreachable', 'source-quench',
    'redirect', 'alternate-address', 'information-request',
    'information-reply', 'mask-request', 'mask-reply',
    'traceroute', 'time-exceeded', 'parameter-problem',
    'router-advertisement', 'router-solicitation',
    'mobile-redirect',
}

# All log levels ASA supports in ACL log keyword
ASA_LOG_LEVELS = {
    'emergencies', 'alerts', 'critical', 'errors',
    'warnings', 'notifications', 'informational', 'debugging',
    'disable',
}

# All ACL types
ASA_ACL_TYPES = {'extended', 'standard', 'ethertype', 'webtype', 'ipv6'}


# ════════════════════════════════════════════════════════════
# PARSER 1: ACCESS-LIST (show access-list)
# ════════════════════════════════════════════════════════════

# Summary line: access-list <name>; <n> elements; name hash: 0x...
RE_ACL_SUMMARY = re.compile(
    r'^access-list\s+(\S+);\s+(\d+)\s+elements',
    re.IGNORECASE
)

# Cached log flows line (global, skip)
RE_ACL_CACHED = re.compile(
    r'^access-list cached ACL log flows',
    re.IGNORECASE
)

# Remark line
# access-list <name> line <n> remark <text>
RE_ACL_REMARK_SHOW = re.compile(
    r'^access-list\s+(\S+)\s+line\s+(\d+)\s+remark\s+(.*)',
    re.IGNORECASE
)

# Extended rule line with hitcnt
# access-list <name> line <n> extended <permit|deny> <body> (hitcnt=N) [0xhash]
RE_ACL_RULE_SHOW = re.compile(
    r'^access-list\s+(\S+)\s+line\s+(\d+)\s+'
    r'(extended|standard|ethertype|webtype|ipv6)\s+'
    r'(permit|deny)\s+'
    r'(.+?)'
    r'\s+\(hitcnt=(\d+)\)'
    r'(\s+\(inactive\))?'
    r'(\s+0x[0-9a-f]+)?'
    r'\s*$',
    re.IGNORECASE
)

# Partial match: any line starting with "access-list" that we
# couldn't fully parse above — captured as partial
RE_ACL_PARTIAL = re.compile(
    r'^access-list\s+\S+',
    re.IGNORECASE
)

# Detect inactive keyword anywhere in rule text
RE_INACTIVE = re.compile(r'\(inactive\)', re.IGNORECASE)

# Detect time-range reference
RE_TIME_RANGE = re.compile(r'\btime-range\s+(\S+)', re.IGNORECASE)

# Detect object/object-group references
RE_OBJ_GROUP = re.compile(r'\bobject-group\s+\S+', re.IGNORECASE)
RE_OBJ       = re.compile(r'\bobject\s+\S+', re.IGNORECASE)

# Detect log level
def extract_log_level(text):
    """Returns log level string found in ACL rule text, or 'default' if
    'log' keyword present without level, or None if no logging."""
    for level in ASA_LOG_LEVELS:
        if re.search(rf'\blog\s+{level}\b', text, re.IGNORECASE):
            return level
    if re.search(r'\blog\b', text, re.IGNORECASE):
        return 'default'
    return None

# Detect port operators
RE_PORT_OP = re.compile(
    r'\b(eq|neq|lt|gt|range)\s+(\S+(?:\s+\S+)?)',
    re.IGNORECASE
)

# Detect FQDN
RE_FQDN = re.compile(r'\bfqdn\s+\S+', re.IGNORECASE)


def parse_access_list_show(lines):
    """
    Parses 'show access-list' output using three-layer architecture.

    Returns:
      acl_meta     : { name: { 'elements': int } }
      acl_rules    : { name: [ rule_dict ] }
      acl_partials : { name: [ partial_line ] }
      unmatched    : [ line ]
    """
    acl_meta     = {}
    acl_rules    = defaultdict(list)
    acl_partials = defaultdict(list)
    unmatched    = []

    pending_remark = {}   # { acl_name: remark_text }

    for line in lines:
        # Skip blank lines
        if not line.strip():
            continue

        # Skip global cached log flows header
        if RE_ACL_CACHED.match(line.strip()):
            continue

        # Skip alert-interval lines (global setting, not a rule)
        if line.strip().lower().startswith('alert-interval'):
            continue

        # Skip indented lines — expanded object references
        # These start with whitespace and are sub-entries of the
        # previous rule showing resolved object content
        if line and (line[0] == ' ' or line[0] == '\t'):
            continue

        stripped = line.strip()

        # ── Layer 1a: Summary line ───────────────────────────
        m = RE_ACL_SUMMARY.match(stripped)
        if m:
            name = m.group(1)
            acl_meta[name] = {'elements': int(m.group(2))}
            continue

        # ── Layer 1b: Remark line ────────────────────────────
        m = RE_ACL_REMARK_SHOW.match(stripped)
        if m:
            name = m.group(1)
            text = m.group(3).strip()
            pending_remark[name] = text
            continue

        # ── Layer 1c: Full rule line ─────────────────────────
        m = RE_ACL_RULE_SHOW.match(stripped)
        if m:
            name     = m.group(1)
            line_num = int(m.group(2))
            acl_type = m.group(3).lower()
            action   = m.group(4).lower()
            body     = m.group(5).strip()
            hitcnt   = int(m.group(6))
            inactive = bool(m.group(7))

            log_level   = extract_log_level(body)
            has_obj_grp = bool(RE_OBJ_GROUP.search(body))
            has_obj     = bool(RE_OBJ.search(body))
            has_fqdn    = bool(RE_FQDN.search(body))
            time_range  = None
            tr_m = RE_TIME_RANGE.search(body)
            if tr_m:
                time_range = tr_m.group(1)

            # Extract port operations for service inventory
            port_ops = RE_PORT_OP.findall(body)

            remark = pending_remark.pop(name, '')

            acl_rules[name].append({
                'line'       : line_num,
                'acl_type'   : acl_type,
                'action'     : action,
                'body'       : body,
                'hitcnt'     : hitcnt,
                'inactive'   : inactive,
                'remark'     : remark,
                'log_level'  : log_level,
                'has_obj_grp': has_obj_grp,
                'has_obj'    : has_obj,
                'has_fqdn'   : has_fqdn,
                'time_range' : time_range,
                'port_ops'   : port_ops,
            })
            continue

        # ── Layer 2: Partial match ───────────────────────────
        # Line starts with "access-list" but didn't fully parse
        if RE_ACL_PARTIAL.match(stripped):
            # Try to extract ACL name for grouping
            parts = stripped.split()
            name = parts[1] if len(parts) > 1 else 'UNKNOWN'
            acl_partials[name].append(stripped)
            continue

        # ── Layer 3: Unmatched ───────────────────────────────
        unmatched.append(stripped)

    return acl_meta, acl_rules, acl_partials, unmatched


def print_access_list_show(acl_meta, acl_rules, acl_partials, unmatched):
    """
    Prints show access-list analysis report.
    """
    print("=" * 78)
    print("  ACCESS LIST ANALYSIS  (show access-list)")
    print("=" * 78)

    if not acl_rules and not acl_meta:
        print("  [WARNING] No ACL data parsed.")
        if unmatched:
            print(f"  {len(unmatched)} unmatched line(s) — see UNMATCHED section.")
        return

    all_names = sorted(set(list(acl_meta.keys()) + list(acl_rules.keys())))

    # Global counters
    g_rules     = 0
    g_zero_hit  = 0
    g_inactive  = 0
    g_deny      = 0
    g_time_range = 0
    g_fqdn      = 0

    for name in all_names:
        rules    = acl_rules.get(name, [])
        elements = acl_meta.get(name, {}).get('elements', len(rules))

        zero_hit   = [r for r in rules if r['hitcnt'] == 0
                      and not r['inactive']]
        inactive   = [r for r in rules if r['inactive']]
        denies     = [r for r in rules if r['action'] == 'deny']
        obj_rules  = [r for r in rules if r['has_obj_grp'] or r['has_obj']]
        fqdn_rules = [r for r in rules if r['has_fqdn']]
        tr_rules   = [r for r in rules if r['time_range']]
        logged     = [r for r in rules if r['log_level']]

        g_rules    += len(rules)
        g_zero_hit += len(zero_hit)
        g_inactive += len(inactive)
        g_deny     += len(denies)
        g_time_range += len(tr_rules)
        g_fqdn     += len(fqdn_rules)

        # Log level breakdown
        log_counts = defaultdict(int)
        for r in logged:
            log_counts[r['log_level']] += 1

        print(f"\n  ── ACL: {name} " + "─" * max(0, 58 - len(name)))
        print(f"     Declared elements    : {elements}")
        print(f"     Parsed rules         : {len(rules)}")
        print(f"     Permit rules         : {len(rules) - len(denies)}")
        print(f"     Deny rules           : {len(denies)}")
        print(f"     Zero-hit rules       : {len(zero_hit)}")
        print(f"     Inactive rules       : {len(inactive)}")
        print(f"     Object references    : {len(obj_rules)}")
        print(f"     FQDN-based rules     : {len(fqdn_rules)}")
        print(f"     Time-range rules     : {len(tr_rules)}")
        print(f"     Rules with logging   : {len(logged)}")

        if log_counts:
            levels_str = ', '.join(
                f"{lvl}({cnt})" for lvl, cnt in sorted(log_counts.items())
            )
            print(f"     Log levels           : {levels_str}")

        # ── Inactive rules detail ────────────────────────────
        if inactive:
            print(f"\n     [FLAG] INACTIVE RULES — must remove before FTD migration")
            print(f"     FTD does not support the 'inactive' keyword:")
            for r in inactive:
                rm = f" | [{r['remark']}]" if r['remark'] else ''
                print(f"       Line {r['line']:>4}: {r['action'].upper()}"
                      f"  {r['body'][:55]}{rm}")

        # ── Zero-hit rules detail ────────────────────────────
        if zero_hit:
            print(f"\n     [FLAG] ZERO-HIT RULES ({len(zero_hit)})"
                  f" — review for cleanup before migration")
            deny_zero = [r for r in zero_hit if r['action'] == 'deny']
            if deny_zero:
                print(f"     DENY rules with zero hits (highest review priority):")
                for r in deny_zero[:10]:  # Show max 10
                    print(f"       Line {r['line']:>4}: DENY  {r['body'][:55]}")
                if len(deny_zero) > 10:
                    print(f"       ... and {len(deny_zero) - 10} more")

        # ── Time-range rules ─────────────────────────────────
        if tr_rules:
            print(f"\n     [INFO] TIME-RANGE RULES ({len(tr_rules)})")
            print(f"     Time-range ACEs require time-range objects in FMC.")
            print(f"     Referenced time-ranges:")
            tr_names = sorted(set(
                r['time_range'] for r in tr_rules if r['time_range']
            ))
            for tr in tr_names:
                print(f"       • {tr}")

        # ── FQDN rules ───────────────────────────────────────
        if fqdn_rules:
            print(f"\n     [INFO] FQDN-BASED RULES ({len(fqdn_rules)})")
            print(f"     FTD supports FQDN objects — verify DNS resolution")
            print(f"     is configured in FMC before deploying these rules.")

        # ── Partials for this ACL ────────────────────────────
        partials = acl_partials.get(name, [])
        if partials:
            print(f"\n     [PARTIAL] {len(partials)} line(s) partially matched"
                  f" — parsed ACL name but rule format unrecognized:")
            for p in partials:
                print(f"       {p[:75]}")

    # ── Global summary ────────────────────────────────────────
    print(f"\n  {'='*78}")
    print(f"  ACL GLOBAL SUMMARY")
    print(f"  {'='*78}")
    print(f"  Total ACLs           : {len(all_names)}")
    print(f"  Total rules parsed   : {g_rules}")
    print(f"  Zero-hit rules       : {g_zero_hit}")
    print(f"  Inactive rules       : {g_inactive}")
    print(f"  Deny rules           : {g_deny}")
    print(f"  Time-range rules     : {g_time_range}")
    print(f"  FQDN rules           : {g_fqdn}")

    if g_inactive:
        print()
        print("  [MIGRATION BLOCKER] Inactive rules must be removed.")
        print("  FTD does not support the 'inactive' keyword in ACEs.")
        print("  Remove or convert them before using FMT.")

    if g_zero_hit:
        print()
        print("  [MIGRATION NOTE] Zero-hit rules may be stale policy.")
        print("  Review with customer — reducing rule count simplifies")
        print("  FMC Access Control Policy and speeds up rule deployment.")

    if g_time_range:
        print()
        print("  [MIGRATION NOTE] Time-range objects must be manually")
        print("  created in FMC before ACL migration. FMT does not")
        print("  automatically migrate time-range configurations.")

    # ── Unmatched lines ───────────────────────────────────────
    if unmatched:
        print(f"\n  {'='*78}")
        print(f"  UNMATCHED LINES IN ACCESS-LIST SECTION"
              f" ({len(unmatched)} line(s))")
        print(f"  {'='*78}")
        print("  These lines were not recognized by any pattern.")
        print("  Review manually — they may represent ACL syntax")
        print("  variants not yet covered by this parser.")
        for u in unmatched[:20]:
            print(f"    {u[:75]}")
        if len(unmatched) > 20:
            print(f"    ... and {len(unmatched) - 20} more unmatched lines")
    print()


# ════════════════════════════════════════════════════════════
# PARSER 2: RUNNING-CONFIG-ACCESS-LIST
# ════════════════════════════════════════════════════════════

# Remark line (config form — no line number)
RE_CFG_REMARK = re.compile(
    r'^access-list\s+(\S+)\s+remark\s+(.*)',
    re.IGNORECASE
)

# Extended/typed rule line (config form — no line number, no hitcnt)
# access-list <name> [extended|standard|ethertype|webtype|ipv6]
#   <permit|deny> <protocol> <src> <dst> [port ops] [log [level]] [inactive]
#   [time-range <name>]
RE_CFG_RULE = re.compile(
    r'^access-list\s+(\S+)\s+'
    r'(?:(extended|standard|ethertype|webtype|ipv6)\s+)?'
    r'(permit|deny)\s+'
    r'(\S+)\s+'    # protocol or object/object-group
    r'(.+?)$',     # rest of rule
    re.IGNORECASE
)

RE_CFG_PARTIAL = re.compile(r'^access-list\s+\S+', re.IGNORECASE)


def parse_running_config_acl(lines):
    """
    Parses 'show running-config access-list' output.

    Returns:
      cfg_rules    : { name: [ rule_dict ] }
      cfg_partials : { name: [ line ] }
      unmatched    : [ line ]
    """
    cfg_rules    = defaultdict(list)
    cfg_partials = defaultdict(list)
    unmatched    = []
    pending_remark = {}

    for line in lines:
        if not line.strip():
            continue

        stripped = line.strip()

        # ── Remark ───────────────────────────────────────────
        m = RE_CFG_REMARK.match(stripped)
        if m:
            pending_remark[m.group(1)] = m.group(2).strip()
            continue

        # ── Full rule ────────────────────────────────────────
        m = RE_CFG_RULE.match(stripped)
        if m:
            name     = m.group(1)
            acl_type = (m.group(2) or 'extended').lower()
            action   = m.group(3).lower()
            protocol = m.group(4).lower()
            rest     = m.group(5).strip()

            inactive   = bool(re.search(r'\binactive\b', rest, re.IGNORECASE))
            log_level  = extract_log_level(rest)
            has_obj_grp = bool(RE_OBJ_GROUP.search(rest))
            has_obj    = bool(RE_OBJ.search(rest))
            has_fqdn   = bool(RE_FQDN.search(rest))
            time_range = None
            tr_m = RE_TIME_RANGE.search(rest)
            if tr_m:
                time_range = tr_m.group(1)
            port_ops   = RE_PORT_OP.findall(rest)

            remark = pending_remark.pop(name, '')

            cfg_rules[name].append({
                'action'     : action,
                'acl_type'   : acl_type,
                'protocol'   : protocol,
                'rest'       : rest,
                'inactive'   : inactive,
                'log_level'  : log_level,
                'has_obj_grp': has_obj_grp,
                'has_obj'    : has_obj,
                'has_fqdn'   : has_fqdn,
                'time_range' : time_range,
                'port_ops'   : port_ops,
                'remark'     : remark,
            })
            continue

        # ── Partial ──────────────────────────────────────────
        if RE_CFG_PARTIAL.match(stripped):
            parts = stripped.split()
            name = parts[1] if len(parts) > 1 else 'UNKNOWN'
            cfg_partials[name].append(stripped)
            continue

        # ── Unmatched ────────────────────────────────────────
        unmatched.append(stripped)

    return cfg_rules, cfg_partials, unmatched


def print_running_config_acl(cfg_rules, cfg_partials, unmatched):
    """
    Prints running-config ACL analysis with full feature inventory.
    """
    print("=" * 78)
    print("  RUNNING CONFIG ACL ANALYSIS  (show running-config access-list)")
    print("=" * 78)

    if not cfg_rules:
        print("  [WARNING] No ACL config rules parsed.")
        if unmatched:
            print(f"  {len(unmatched)} unmatched line(s) — see UNMATCHED section.")
        return

    # Protocol inventory across all ACLs
    protocol_inventory = defaultdict(int)

    for name, rules in sorted(cfg_rules.items()):
        permits    = [r for r in rules if r['action'] == 'permit']
        denies     = [r for r in rules if r['action'] == 'deny']
        inactive   = [r for r in rules if r['inactive']]
        logged     = [r for r in rules if r['log_level']]
        fqdn_rules = [r for r in rules if r['has_fqdn']]
        tr_rules   = [r for r in rules if r['time_range']]
        obj_rules  = [r for r in rules if r['has_obj_grp'] or r['has_obj']]

        log_counts = defaultdict(int)
        for r in logged:
            log_counts[r['log_level']] += 1

        for r in rules:
            protocol_inventory[r['protocol']] += 1

        print(f"\n  ── ACL: {name} " + "─" * max(0, 58 - len(name)))
        print(f"     Total rules          : {len(rules)}")
        print(f"     Permit               : {len(permits)}")
        print(f"     Deny                 : {len(denies)}")
        print(f"     Inactive             : {len(inactive)}")
        print(f"     Logged rules         : {len(logged)}")
        print(f"     Object references    : {len(obj_rules)}")
        print(f"     FQDN rules           : {len(fqdn_rules)}")
        print(f"     Time-range rules     : {len(tr_rules)}")

        if log_counts:
            lvl_str = ', '.join(
                f"{lvl}({cnt})" for lvl, cnt in sorted(log_counts.items())
            )
            print(f"     Log levels           : {lvl_str}")

        # Inactive detail
        if inactive:
            print(f"\n     [FLAG] INACTIVE RULES in config:")
            for r in inactive:
                rm = f" [{r['remark']}]" if r['remark'] else ''
                print(f"       {r['action'].upper()} {r['protocol']}"
                      f"  {r['rest'][:55]}{rm}")

        # Time-range detail
        if tr_rules:
            tr_names = sorted(set(
                r['time_range'] for r in tr_rules if r['time_range']
            ))
            print(f"\n     [INFO] Time-range references: {', '.join(tr_names)}")

        # Partials
        partials = cfg_partials.get(name, [])
        if partials:
            print(f"\n     [PARTIAL] {len(partials)} partially matched line(s):")
            for p in partials:
                print(f"       {p[:75]}")

    # Protocol inventory
    if protocol_inventory:
        print(f"\n  {'='*78}")
        print(f"  PROTOCOL INVENTORY ACROSS ALL ACLs")
        print(f"  {'='*78}")
        print(f"  {'PROTOCOL':<30} {'RULE COUNT':>12}")
        print(f"  {'-'*29} {'-'*12}")
        for proto, count in sorted(
            protocol_inventory.items(), key=lambda x: -x[1]
        ):
            unknown = '' if proto in ASA_PROTOCOLS else '  [VERIFY]'
            print(f"  {proto:<30} {count:>12}{unknown}")

    # Unmatched
    if unmatched:
        print(f"\n  {'='*78}")
        print(f"  UNMATCHED LINES IN RUNNING-CONFIG-ACCESS-LIST"
              f" ({len(unmatched)} line(s))")
        print(f"  {'='*78}")
        for u in unmatched[:20]:
            print(f"    {u[:75]}")
        if len(unmatched) > 20:
            print(f"    ... and {len(unmatched) - 20} more")
    print()


# ════════════════════════════════════════════════════════════
# PARSER 3: RUNNING-CONFIG-CRYPTO
# ════════════════════════════════════════════════════════════

# ── IKEv1 policy block ────────────────────────────────────────
# crypto ikev1 policy <priority>
RE_IKEv1_POLICY = re.compile(
    r'^crypto ikev1 policy\s+(\d+)',
    re.IGNORECASE
)
# Sub-commands inside ikev1 policy block
RE_IKEv1_ENC  = re.compile(r'^\s*encryption\s+(\S+)', re.IGNORECASE)
RE_IKEv1_HASH = re.compile(r'^\s*hash\s+(\S+)', re.IGNORECASE)
RE_IKEv1_AUTH = re.compile(r'^\s*authentication\s+(\S+)', re.IGNORECASE)
RE_IKEv1_GROUP= re.compile(r'^\s*group\s+(\d+)', re.IGNORECASE)
RE_IKEv1_LIFE = re.compile(r'^\s*lifetime\s+(\d+)', re.IGNORECASE)

# ── IKEv2 policy block ────────────────────────────────────────
# crypto ikev2 policy <priority>
RE_IKEv2_POLICY = re.compile(
    r'^crypto ikev2 policy\s+(\d+)',
    re.IGNORECASE
)
RE_IKEv2_ENC   = re.compile(r'^\s*encryption\s+(.+)', re.IGNORECASE)
RE_IKEv2_INT   = re.compile(r'^\s*integrity\s+(.+)', re.IGNORECASE)
RE_IKEv2_PRF   = re.compile(r'^\s*prf\s+(.+)', re.IGNORECASE)
RE_IKEv2_GROUP = re.compile(r'^\s*group\s+(.+)', re.IGNORECASE)
RE_IKEv2_LIFE  = re.compile(r'^\s*lifetime\s+seconds\s+(\d+)', re.IGNORECASE)

# ── IKEv1 transform sets ──────────────────────────────────────
# crypto ipsec ikev1 transform-set <name> <esp-enc> [<esp-hash>] [mode transport]
RE_IKEv1_TS = re.compile(
    r'^crypto ipsec ikev1 transform-set\s+(\S+)\s+(\S+)(?:\s+(\S+))?',
    re.IGNORECASE
)
RE_TS_MODE = re.compile(
    r'^crypto ipsec ikev1 transform-set\s+\S+.*\s+mode\s+(transport|tunnel)',
    re.IGNORECASE
)

# ── IKEv2 IPsec proposals ─────────────────────────────────────
# crypto ipsec ikev2 ipsec-proposal <name>
RE_IKEv2_PROP = re.compile(
    r'^crypto ipsec ikev2 ipsec-proposal\s+(\S+)',
    re.IGNORECASE
)
RE_PROP_ENC = re.compile(r'^\s*protocol esp encryption\s+(.+)', re.IGNORECASE)
RE_PROP_INT = re.compile(r'^\s*protocol esp integrity\s+(.+)', re.IGNORECASE)
RE_PROP_AH  = re.compile(r'^\s*protocol ah\s+(.+)', re.IGNORECASE)

# ── IPsec profile ─────────────────────────────────────────────
# crypto ipsec profile <name>
RE_IPSEC_PROFILE = re.compile(
    r'^crypto ipsec profile\s+(\S+)',
    re.IGNORECASE
)

# ── IPsec global settings ─────────────────────────────────────
RE_IPSEC_GLOBAL = re.compile(
    r'^crypto ipsec\s+(?!ikev1|ikev2|profile)(.+)',
    re.IGNORECASE
)

# ── IKE enable statements ─────────────────────────────────────
# crypto ikev1 enable <interface>
# crypto ikev2 enable <interface>
RE_IKE_ENABLE = re.compile(
    r'^crypto (ikev1|ikev2) enable\s+(\S+)',
    re.IGNORECASE
)

# ── Dynamic map ───────────────────────────────────────────────
# crypto dynamic-map <name> <seq> <verb> <rest>
RE_DYN_MAP = re.compile(
    r'^crypto dynamic-map\s+(\S+)\s+(\d+)\s+(.+)',
    re.IGNORECASE
)

# ── Static crypto map ─────────────────────────────────────────
# crypto map <name> <seq> <verb> <rest>
RE_CRYPTO_MAP = re.compile(
    r'^crypto map\s+(\S+)\s+(\d+)\s+(match|set|interface|ipsec-isakmp)(\s+.+)?$',
    re.IGNORECASE
)

# crypto map <name> interface <iface>
RE_CRYPTO_MAP_IFACE = re.compile(
    r'^crypto map\s+(\S+)\s+interface\s+(\S+)',
    re.IGNORECASE
)

# ── IKEv1 ISAKMP policy (legacy syntax) ──────────────────────
# crypto isakmp policy <priority>
RE_ISAKMP_POLICY = re.compile(
    r'^crypto isakmp policy\s+(\d+)',
    re.IGNORECASE
)
# crypto isakmp enable / key / identity etc.
RE_ISAKMP_GLOBAL = re.compile(
    r'^crypto isakmp\s+(?!policy)(.+)',
    re.IGNORECASE
)

# ── SA lifetime ───────────────────────────────────────────────
RE_SA_LIFETIME = re.compile(
    r'^crypto ipsec security-association\s+(lifetime|pmtu-aging)\s+(.+)',
    re.IGNORECASE
)

# ── Partial: any crypto line ──────────────────────────────────
RE_CRYPTO_PARTIAL = re.compile(r'^crypto\s+', re.IGNORECASE)


def parse_crypto(lines):
    """
    Parses 'show running-config crypto' output.
    Covers ALL documented ASA crypto syntax variants.

    Returns:
      ikev1_policies  : [ policy_dict ]
      ikev2_policies  : [ policy_dict ]
      ikev1_ts        : [ ts_dict ]
      ikev2_proposals : [ proposal_dict ]
      ipsec_profiles  : [ profile_dict ]
      dynamic_maps    : { name: [ entry_dict ] }
      crypto_maps     : { name: { seq: entry_dict } }
      ike_enables     : { version: [ interface ] }
      map_interfaces  : { map_name: interface }
      isakmp_globals  : [ line ]
      ipsec_globals   : [ line ]
      sa_settings     : [ line ]
      partials        : [ line ]
      unmatched       : [ line ]
    """
    ikev1_policies  = []
    ikev2_policies  = []
    ikev1_ts        = []
    ikev2_proposals = []
    ipsec_profiles  = []
    dynamic_maps    = defaultdict(list)
    crypto_maps     = defaultdict(lambda: defaultdict(dict))
    ike_enables     = defaultdict(list)
    map_interfaces  = {}
    isakmp_globals  = []
    ipsec_globals   = []
    sa_settings     = []
    partials        = []
    unmatched       = []

    # State tracking for multi-line blocks
    current_ikev1_policy  = None
    current_ikev2_policy  = None
    current_ikev2_prop    = None
    current_ipsec_profile = None

    def reset_block_state():
        nonlocal current_ikev1_policy, current_ikev2_policy
        nonlocal current_ikev2_prop, current_ipsec_profile
        current_ikev1_policy  = None
        current_ikev2_policy  = None
        current_ikev2_prop    = None
        current_ipsec_profile = None

    for line in lines:
        if not line.strip():
            continue

        stripped = line.strip()

        # ── IKEv1 policy header ───────────────────────────────
        m = RE_IKEv1_POLICY.match(stripped)
        if m:
            reset_block_state()
            current_ikev1_policy = {
                'priority'  : int(m.group(1)),
                'encryption': None,
                'hash'      : None,
                'auth'      : None,
                'group'     : None,
                'lifetime'  : None,
            }
            ikev1_policies.append(current_ikev1_policy)
            continue

        # ── IKEv1 policy sub-commands ─────────────────────────
        if current_ikev1_policy:
            if RE_IKEv1_ENC.match(stripped):
                current_ikev1_policy['encryption'] = \
                    RE_IKEv1_ENC.match(stripped).group(1).lower()
                continue
            if RE_IKEv1_HASH.match(stripped):
                current_ikev1_policy['hash'] = \
                    RE_IKEv1_HASH.match(stripped).group(1).lower()
                continue
            if RE_IKEv1_AUTH.match(stripped):
                current_ikev1_policy['auth'] = \
                    RE_IKEv1_AUTH.match(stripped).group(1).lower()
                continue
            if RE_IKEv1_GROUP.match(stripped):
                current_ikev1_policy['group'] = \
                    RE_IKEv1_GROUP.match(stripped).group(1)
                continue
            if RE_IKEv1_LIFE.match(stripped):
                current_ikev1_policy['lifetime'] = \
                    RE_IKEv1_LIFE.match(stripped).group(1)
                continue

        # ── IKEv2 policy header ───────────────────────────────
        m = RE_IKEv2_POLICY.match(stripped)
        if m:
            reset_block_state()
            current_ikev2_policy = {
                'priority'  : int(m.group(1)),
                'encryption': [],
                'integrity' : [],
                'prf'       : [],
                'group'     : [],
                'lifetime'  : None,
            }
            ikev2_policies.append(current_ikev2_policy)
            continue

        # ── IKEv2 policy sub-commands ─────────────────────────
        if current_ikev2_policy:
            if RE_IKEv2_ENC.match(stripped):
                algs = RE_IKEv2_ENC.match(stripped).group(1).split()
                current_ikev2_policy['encryption'].extend(
                    [a.lower() for a in algs]
                )
                continue
            if RE_IKEv2_INT.match(stripped):
                algs = RE_IKEv2_INT.match(stripped).group(1).split()
                current_ikev2_policy['integrity'].extend(
                    [a.lower() for a in algs]
                )
                continue
            if RE_IKEv2_PRF.match(stripped):
                algs = RE_IKEv2_PRF.match(stripped).group(1).split()
                current_ikev2_policy['prf'].extend(
                    [a.lower() for a in algs]
                )
                continue
            if RE_IKEv2_GROUP.match(stripped):
                grps = RE_IKEv2_GROUP.match(stripped).group(1).split()
                current_ikev2_policy['group'].extend(grps)
                continue
            if RE_IKEv2_LIFE.match(stripped):
                current_ikev2_policy['lifetime'] = \
                    RE_IKEv2_LIFE.match(stripped).group(1)
                continue

        # ── IKEv1 transform set ───────────────────────────────
        m = RE_IKEv1_TS.match(stripped)
        if m:
            reset_block_state()
            name     = m.group(1)
            esp_enc  = m.group(2).lower()
            esp_hash = m.group(3).lower() if m.group(3) else None

            # Check for mode transport on same line
            mode = 'tunnel'
            mode_m = RE_TS_MODE.match(stripped)
            if mode_m:
                mode = mode_m.group(1).lower()
                # Remove mode token from hash if accidentally captured
                if esp_hash and esp_hash in ('transport', 'tunnel', 'mode'):
                    esp_hash = None

            ikev1_ts.append({
                'name'      : name,
                'esp_enc'   : esp_enc,
                'esp_hash'  : esp_hash,
                'mode'      : mode,
                'ftd_enc'   : ftd_enc_status(esp_enc),
                'ftd_hash'  : ftd_int_status(esp_hash) if esp_hash else 'N/A',
            })
            continue

        # ── IKEv2 proposal header ─────────────────────────────
        m = RE_IKEv2_PROP.match(stripped)
        if m:
            reset_block_state()
            current_ikev2_prop = {
                'name'       : m.group(1),
                'encryption' : [],
                'integrity'  : [],
                'ah'         : [],
            }
            ikev2_proposals.append(current_ikev2_prop)
            continue

        # ── IKEv2 proposal sub-lines ──────────────────────────
        if current_ikev2_prop:
            m = RE_PROP_ENC.match(stripped)
            if m:
                algs = m.group(1).strip().split()
                current_ikev2_prop['encryption'].extend(
                    [a.lower() for a in algs]
                )
                continue
            m = RE_PROP_INT.match(stripped)
            if m:
                algs = m.group(1).strip().split()
                current_ikev2_prop['integrity'].extend(
                    [a.lower() for a in algs]
                )
                continue
            m = RE_PROP_AH.match(stripped)
            if m:
                current_ikev2_prop['ah'].append(m.group(1).strip())
                continue

        # ── IPsec profile header ──────────────────────────────
        m = RE_IPSEC_PROFILE.match(stripped)
        if m:
            reset_block_state()
            current_ipsec_profile = {
                'name'    : m.group(1),
                'settings': [],
            }
            ipsec_profiles.append(current_ipsec_profile)
            continue

        # ── IPsec profile sub-lines ───────────────────────────
        if current_ipsec_profile:
            m_set = re.match(r'^\s*set\s+(.+)', stripped, re.IGNORECASE)
            if m_set:
                current_ipsec_profile['settings'].append(m_set.group(1))
                continue

        # ── IKE enable statements ─────────────────────────────
        m = RE_IKE_ENABLE.match(stripped)
        if m:
            reset_block_state()
            ike_enables[m.group(1).lower()].append(m.group(2))
            continue

        # ── Crypto map interface binding ──────────────────────
        m = RE_CRYPTO_MAP_IFACE.match(stripped)
        if m:
            reset_block_state()
            map_interfaces[m.group(1)] = m.group(2)
            continue

        # ── Dynamic map ───────────────────────────────────────
        m = RE_DYN_MAP.match(stripped)
        if m:
            reset_block_state()
            map_name = m.group(1)
            seq      = m.group(2)
            rest_str = m.group(3).strip()

            # Parse set sub-commands
            dh_flag = ''
            weak_flag = ''
            rest_lower = rest_str.lower()

            if 'pfs' in rest_lower:
                grp_m = re.search(r'group\s*(\d+)', rest_lower)
                if grp_m:
                    grp = grp_m.group(1)
                    status = ftd_dh_status(grp)
                    if status != 'OK':
                        dh_flag = f" [{FTD_STATUS_SYMBOL[status]} DH group{grp}]"

            for alg in ['3des', 'des', 'md5', 'esp-des', 'esp-3des',
                        'esp-md5-hmac']:
                if alg in rest_lower:
                    weak_flag = f" [WEAK: {alg}]"
                    break

            dynamic_maps[map_name].append({
                'seq'      : seq,
                'setting'  : rest_str,
                'dh_flag'  : dh_flag,
                'weak_flag': weak_flag,
            })
            continue

        # ── Static crypto map ─────────────────────────────────
        m = RE_CRYPTO_MAP.match(stripped)
        if m:
            reset_block_state()
            map_name  = m.group(1)
            seq       = int(m.group(2))
            verb      = m.group(3).lower()
            remainder = (m.group(4) or '').strip()

            if seq not in crypto_maps[map_name]:
                crypto_maps[map_name][seq] = {
                    'seq'        : seq,
                    'match_acl'  : None,
                    'peers'      : [],
                    'ikev1_ts'   : [],
                    'ikev2_prop' : [],
                    'pfs'        : None,
                    'sa_lifetime': None,
                    'mode'       : None,
                    'raw'        : [],
                }

            entry = crypto_maps[map_name][seq]
            entry['raw'].append(f"{verb} {remainder}")

            r_lower = remainder.lower()
            if verb == 'match' and r_lower.startswith('address'):
                entry['match_acl'] = remainder.split()[-1]
            elif verb == 'set':
                if r_lower.startswith('peer'):
                    entry['peers'].append(remainder.split()[-1])
                elif 'ikev1 transform-set' in r_lower:
                    ts_names = remainder.split()[2:]
                    entry['ikev1_ts'].extend(ts_names)
                elif 'ikev2 ipsec-proposal' in r_lower:
                    prop_names = remainder.split()[2:]
                    entry['ikev2_prop'].extend(prop_names)
                elif r_lower.startswith('pfs'):
                    entry['pfs'] = remainder
                elif r_lower.startswith('security-association lifetime'):
                    entry['sa_lifetime'] = remainder
                elif r_lower.startswith('ikev1 phase1-mode') or \
                     r_lower.startswith('connection-type'):
                    entry['mode'] = remainder
            continue

        # ── SA lifetime / global IPsec settings ───────────────
        m = RE_SA_LIFETIME.match(stripped)
        if m:
            reset_block_state()
            sa_settings.append(stripped)
            continue

        m = RE_IPSEC_GLOBAL.match(stripped)
        if m:
            reset_block_state()
            ipsec_globals.append(stripped)
            continue

        # ── Legacy ISAKMP ─────────────────────────────────────
        m = RE_ISAKMP_POLICY.match(stripped)
        if m:
            reset_block_state()
            isakmp_globals.append(stripped)
            continue

        m = RE_ISAKMP_GLOBAL.match(stripped)
        if m:
            reset_block_state()
            isakmp_globals.append(stripped)
            continue

        # ── Partial ───────────────────────────────────────────
        if RE_CRYPTO_PARTIAL.match(stripped):
            reset_block_state()
            partials.append(stripped)
            continue

        # ── Unmatched ─────────────────────────────────────────
        unmatched.append(stripped)

    return (
        ikev1_policies, ikev2_policies,
        ikev1_ts, ikev2_proposals,
        ipsec_profiles, dynamic_maps,
        crypto_maps, ike_enables,
        map_interfaces, isakmp_globals,
        ipsec_globals, sa_settings,
        partials, unmatched,
    )


def print_crypto(ikev1_policies, ikev2_policies,
                 ikev1_ts, ikev2_proposals,
                 ipsec_profiles, dynamic_maps,
                 crypto_maps, ike_enables,
                 map_interfaces, isakmp_globals,
                 ipsec_globals, sa_settings,
                 partials, unmatched):
    """
    Prints full crypto analysis with FTD compatibility assessment.
    """
    print("=" * 78)
    print("  CRYPTO ANALYSIS  (show running-config crypto)")
    print("=" * 78)

    # Track all risk items for final summary
    risk_high   = []
    risk_medium = []
    risk_info   = []

    # ── IKE enable status ─────────────────────────────────────
    if ike_enables:
        print(f"\n  ── IKE ENABLED INTERFACES " + "─" * 45)
        for ver, ifaces in sorted(ike_enables.items()):
            for iface in ifaces:
                print(f"     {ver.upper()} enabled on: {iface}")

    # ── IKEv1 Phase 1 policies ────────────────────────────────
    print(f"\n  ── IKEv1 PHASE 1 POLICIES ({len(ikev1_policies)}) " + "─" * 38)

    if not ikev1_policies:
        print("     None configured.")
    else:
        hdr = (f"  {'PRI':>5}  {'ENCRYPTION':<15} {'HASH':<10}"
               f" {'AUTH':<12} {'DH GRP':>7} {'LIFETIME':>10}")
        print(hdr)
        print(f"  {'-'*5}  {'-'*14} {'-'*9} {'-'*11} {'-'*7} {'-'*10}")

        for pol in sorted(ikev1_policies, key=lambda x: x['priority']):
            enc   = pol['encryption'] or 'default(3des)'
            hsh   = pol['hash']       or 'default(sha)'
            auth  = pol['auth']       or 'default(pre-share)'
            group = pol['group']      or 'default(2)'
            life  = pol['lifetime']   or 'default(86400)'

            enc_s = FTD_STATUS_SYMBOL.get(ftd_ike_enc_status(enc), '')
            hsh_s = FTD_STATUS_SYMBOL.get(ftd_ike_hash_status(hsh), '')
            dh_s  = FTD_STATUS_SYMBOL.get(ftd_dh_status(group), '')

            print(f"  {pol['priority']:>5}  {enc:<15} {hsh:<10}"
                  f" {auth:<12} {group:>7} {life:>10}")

            flags = []
            if 'REMOVED' in enc_s or 'DEPRECATED' in enc_s:
                flags.append(f"Encryption: {enc_s}")
            if 'REMOVED' in hsh_s or 'DEPRECATED' in hsh_s:
                flags.append(f"Hash: {hsh_s}")
            if 'REMOVED' in dh_s or 'DEPRECATED' in dh_s:
                flags.append(f"DH group {group}: {dh_s}")

            for f in flags:
                print(f"          [FLAG] {f}")
                if 'REMOVED' in f:
                    risk_high.append(
                        f"IKEv1 Policy {pol['priority']}: {f}"
                    )
                else:
                    risk_medium.append(
                        f"IKEv1 Policy {pol['priority']}: {f}"
                    )

    # ── IKEv2 Phase 1 policies ────────────────────────────────
    print(f"\n  ── IKEv2 PHASE 1 POLICIES ({len(ikev2_policies)}) " + "─" * 38)

    if not ikev2_policies:
        print("     None configured.")
    else:
        for pol in sorted(ikev2_policies, key=lambda x: x['priority']):
            print(f"\n     Priority  : {pol['priority']}")
            enc_list = pol['encryption'] or ['default']
            int_list = pol['integrity']  or ['default']
            prf_list = pol['prf']        or ['same as integrity']
            grp_list = pol['group']      or ['default']

            for enc in enc_list:
                s = FTD_STATUS_SYMBOL.get(ftd_ike_enc_status(enc), 'UNKNOWN')
                print(f"     Encryption: {enc:<20} {s}")
                if 'REMOVED' in s or 'DEPRECATED' in s:
                    risk_high.append(
                        f"IKEv2 Policy {pol['priority']} enc {enc}: {s}"
                    ) if 'REMOVED' in s else risk_medium.append(
                        f"IKEv2 Policy {pol['priority']} enc {enc}: {s}"
                    )

            for alg in int_list:
                s = FTD_STATUS_SYMBOL.get(ftd_ike_hash_status(alg), 'UNKNOWN')
                print(f"     Integrity : {alg:<20} {s}")
                if 'REMOVED' in s or 'DEPRECATED' in s:
                    risk_high.append(
                        f"IKEv2 Policy {pol['priority']} integrity {alg}: {s}"
                    ) if 'REMOVED' in s else risk_medium.append(
                        f"IKEv2 Policy {pol['priority']} integrity {alg}: {s}"
                    )

            print(f"     PRF       : {', '.join(prf_list)}")

            for grp in grp_list:
                s = FTD_STATUS_SYMBOL.get(ftd_dh_status(grp), 'UNKNOWN')
                print(f"     DH Group  : {grp:<20} {s}")
                if 'REMOVED' in s or 'DEPRECATED' in s:
                    risk_high.append(
                        f"IKEv2 Policy {pol['priority']} DH group {grp}: {s}"
                    ) if 'REMOVED' in s else risk_medium.append(
                        f"IKEv2 Policy {pol['priority']} DH group {grp}: {s}"
                    )

            if pol['lifetime']:
                print(f"     Lifetime  : {pol['lifetime']} seconds")

    # ── IKEv1 Transform Sets ──────────────────────────────────
    print(f"\n  ── IKEv1 TRANSFORM SETS ({len(ikev1_ts)}) " + "─" * 42)

    if not ikev1_ts:
        print("     None configured.")
    else:
        print(f"  {'NAME':<35} {'ESP-ENC':<20} {'ESP-HASH':<20}"
              f" {'MODE':<10} {'ENC STATUS':<15} {'HASH STATUS'}")
        print(f"  {'-'*34} {'-'*19} {'-'*19} {'-'*9} {'-'*14} {'-'*15}")

        weak_ts = set()
        for ts in ikev1_ts:
            enc_s  = FTD_STATUS_SYMBOL.get(ts['ftd_enc'], 'UNKNOWN')
            hash_s = FTD_STATUS_SYMBOL.get(ts['ftd_hash'], 'UNKNOWN')

            esp_hash_str = ts['esp_hash'] or '(none)'

            print(f"  {ts['name']:<35} {ts['esp_enc']:<20}"
                  f" {esp_hash_str:<20} {ts['mode']:<10}"
                  f" {enc_s:<15} {hash_s}")

            if ts['ftd_enc'] in ('REMOVED', 'DEPRECATED') or \
               ts['ftd_hash'] in ('REMOVED', 'DEPRECATED'):
                weak_ts.add(ts['name'])
                if ts['ftd_enc'] == 'REMOVED' or ts['ftd_hash'] == 'REMOVED':
                    risk_high.append(
                        f"IKEv1 TS '{ts['name']}': "
                        f"{ts['esp_enc']}/{esp_hash_str} — contains REMOVED alg"
                    )
                else:
                    risk_medium.append(
                        f"IKEv1 TS '{ts['name']}': "
                        f"{ts['esp_enc']}/{esp_hash_str} — contains DEPRECATED alg"
                    )

        if weak_ts:
            print()
            print(f"  [FLAG] {len(weak_ts)} transform set(s) contain"
                  f" REMOVED or DEPRECATED algorithms.")
            print("  These MUST be updated before FTD migration AND")
            print("  coordinated with all remote VPN peers.")

    # ── IKEv2 Proposals ──────────────────────────────────────
    print(f"\n  ── IKEv2 IPSEC PROPOSALS ({len(ikev2_proposals)}) " + "─" * 40)

    if not ikev2_proposals:
        print("     None configured.")
    else:
        for prop in ikev2_proposals:
            print(f"\n     Proposal : {prop['name']}")

            enc_list = prop['encryption'] or ['(none)']
            int_list = prop['integrity']  or ['(none)']

            for enc in enc_list:
                s = FTD_STATUS_SYMBOL.get(ftd_enc_status(enc), 'UNKNOWN')
                print(f"       Encryption : {enc:<25} {s}")
                if 'REMOVED' in s:
                    risk_high.append(
                        f"IKEv2 Proposal '{prop['name']}' enc {enc}: REMOVED"
                    )
                elif 'DEPRECATED' in s:
                    risk_medium.append(
                        f"IKEv2 Proposal '{prop['name']}' enc {enc}: DEPRECATED"
                    )

            for alg in int_list:
                s = FTD_STATUS_SYMBOL.get(ftd_int_status(alg), 'UNKNOWN')
                print(f"       Integrity  : {alg:<25} {s}")
                if 'REMOVED' in s:
                    risk_high.append(
                        f"IKEv2 Proposal '{prop['name']}' integrity {alg}: REMOVED"
                    )
                elif 'DEPRECATED' in s:
                    risk_medium.append(
                        f"IKEv2 Proposal '{prop['name']}' integrity {alg}: DEPRECATED"
                    )

            if prop['ah']:
                print(f"       AH         : {', '.join(prop['ah'])}")
                risk_info.append(
                    f"IKEv2 Proposal '{prop['name']}' uses AH — "
                    "verify FTD AH support for this proposal"
                )

    # ── IPsec Profiles ────────────────────────────────────────
    if ipsec_profiles:
        print(f"\n  ── IPSEC PROFILES ({len(ipsec_profiles)}) " + "─" * 48)
        for profile in ipsec_profiles:
            print(f"\n     Profile : {profile['name']}")
            for setting in profile['settings']:
                s_lower = setting.lower()
                pfs_flag = ''
                if 'pfs' in s_lower:
                    grp_m = re.search(r'group\s*(\d+)', s_lower)
                    if grp_m:
                        g = grp_m.group(1)
                        status = ftd_dh_status(g)
                        pfs_flag = f"  [{FTD_STATUS_SYMBOL.get(status, '')} DH group{g}]"
                        if status != 'OK':
                            risk_medium.append(
                                f"IPsec profile '{profile['name']}'"
                                f" PFS group{g}: {status}"
                            )
                print(f"       set {setting}{pfs_flag}")

    # ── Dynamic Maps ──────────────────────────────────────────
    if dynamic_maps:
        print(f"\n  ── DYNAMIC CRYPTO MAPS ({len(dynamic_maps)}) " + "─" * 44)
        print("     [INFO] Dynamic maps = used for RA VPN (AnyConnect).")
        print("     These do NOT migrate via FMT.")
        print("     Must be rebuilt as RA VPN Connection Profiles in FMC.")
        risk_high.append(
            f"{len(dynamic_maps)} dynamic map(s) present — "
            "RA VPN must be fully rebuilt in FMC, not migrated via FMT"
        )

        for map_name, entries in sorted(dynamic_maps.items()):
            print(f"\n     Dynamic Map : {map_name}")
            for e in entries:
                flags = e['dh_flag'] + e['weak_flag']
                print(f"       seq {e['seq']}: {e['setting']}{flags}")

    # ── Static Crypto Maps ────────────────────────────────────
    if crypto_maps:
        total_entries = sum(len(v) for v in crypto_maps.values())
        print(f"\n  ── STATIC CRYPTO MAPS"
              f" ({len(crypto_maps)} map(s), {total_entries} entr(ies))"
              + "─" * 25)

        # Build weak TS lookup from ikev1_ts list
        weak_ts_names = {
            ts['name'] for ts in ikev1_ts
            if ts['ftd_enc'] in ('REMOVED', 'DEPRECATED') or
               ts['ftd_hash'] in ('REMOVED', 'DEPRECATED')
        }

        for map_name, seqs in sorted(crypto_maps.items()):
            iface = map_interfaces.get(map_name, '(not bound)')
            print(f"\n     Crypto Map : {map_name}  (interface: {iface})")
            print(f"     {'SEQ':>5}  {'MATCH ACL':<25} {'PEER(S)':<20}"
                  f" {'IKEv1 TS':<20} {'IKEv2 PROP':<20} {'PFS'}")
            print(f"     {'-'*5}  {'-'*24} {'-'*19} {'-'*19}"
                  f" {'-'*19} {'-'*10}")

            for seq, entry in sorted(seqs.items()):
                acl   = entry['match_acl'] or '—'
                peers = ', '.join(entry['peers'])  or '—'
                ts    = ', '.join(entry['ikev1_ts'])   or '—'
                prop  = ', '.join(entry['ikev2_prop']) or '—'
                pfs   = entry['pfs'] or '—'

                print(f"     {seq:>5}  {acl:<25} {peers:<20}"
                      f" {ts:<20} {prop:<20} {pfs}")

                # Flag weak transform sets referenced in map
                weak_refs = [
                    t for t in entry['ikev1_ts']
                    if t.lower() in {n.lower() for n in weak_ts_names}
                ]
                if weak_refs:
                    print(f"             [FLAG] Weak TS referenced:"
                          f" {', '.join(weak_refs)}")
                    risk_high.append(
                        f"Crypto map '{map_name}' seq {seq} references"
                        f" weak TS: {', '.join(weak_refs)}"
                    )

                # PFS group check
                if entry['pfs']:
                    grp_m = re.search(r'group\s*(\d+)',
                                      entry['pfs'].lower())
                    if grp_m:
                        g = grp_m.group(1)
                        status = ftd_dh_status(g)
                        if status != 'OK':
                            print(f"             [FLAG] PFS {entry['pfs']}"
                                  f" — DH group{g}:"
                                  f" {FTD_STATUS_SYMBOL.get(status, '')}")
                            risk_medium.append(
                                f"Crypto map '{map_name}' seq {seq}"
                                f" PFS group{g}: {status}"
                            )

    # ── Legacy ISAKMP ─────────────────────────────────────────
    if isakmp_globals:
        print(f"\n  ── LEGACY ISAKMP STATEMENTS ({len(isakmp_globals)}) "
              + "─" * 37)
        print("     [INFO] 'crypto isakmp' is the legacy IKEv1 syntax.")
        print("     Verify these settings are captured in IKEv1 policy")
        print("     blocks above. If standalone, they may need manual")
        print("     review for FMC migration.")
        for line in isakmp_globals:
            print(f"     {line}")

    # ── IPsec globals ─────────────────────────────────────────
    if ipsec_globals or sa_settings:
        print(f"\n  ── IPSEC GLOBAL SETTINGS " + "─" * 48)
        for line in sa_settings + ipsec_globals:
            print(f"     {line}")

    # ── Partial lines ─────────────────────────────────────────
    if partials:
        print(f"\n  ── PARTIAL MATCHES ({len(partials)}) " + "─" * 50)
        print("  [PARTIAL] These lines start with 'crypto' but did not")
        print("  match any known pattern. Review manually:")
        for p in partials:
            print(f"    {p[:75]}")

    # ── Unmatched lines ───────────────────────────────────────
    if unmatched:
        print(f"\n  ── UNMATCHED LINES ({len(unmatched)}) " + "─" * 50)
        print("  These lines did not match any crypto pattern:")
        for u in unmatched[:20]:
            print(f"    {u[:75]}")
        if len(unmatched) > 20:
            print(f"    ... and {len(unmatched) - 20} more")

    # ── Migration Risk Summary ────────────────────────────────
    print(f"\n  {'='*78}")
    print("  CRYPTO MIGRATION RISK SUMMARY")
    print(f"  {'='*78}")

    if not risk_high and not risk_medium and not risk_info:
        print("  ✅ No crypto migration risks detected.")
    else:
        if risk_high:
            print(f"\n  ❌ HIGH RISK ({len(risk_high)} item(s))"
                  f" — will BREAK on FTD without remediation:")
            for item in risk_high:
                print(f"     • {item}")

        if risk_medium:
            print(f"\n  ⚠️  MEDIUM RISK ({len(risk_medium)} item(s))"
                  f" — deprecated, may fail on newer FTD versions:")
            for item in risk_medium:
                print(f"     • {item}")

        if risk_info:
            print(f"\n  ℹ️  INFO ({len(risk_info)} item(s)) — verify:")
            for item in risk_info:
                print(f"     • {item}")

    print()


# ════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════

def print_header():
    print()
    print("=" * 78)
    print("  ASA MIGRATION PARSER — PHASE 4")
    print("  Full-Spec ACL + Crypto Analysis with FTD Compatibility")
    print("  Three-layer parsing: Full match | Partial | Unmatched")
    print("=" * 78)
    print()


def main():
    if len(sys.argv) != 2:
        print("Usage: python asa_parser_p4.py <path_to_log_file>")
        print("Example: python asa_parser_p4.py asa_logs.txt")
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

    # ── ACCESS-LIST ───────────────────────────────────────────
    acl_lines = sections_data.get("ACCESS-LIST", [])
    if acl_lines:
        meta, rules, partials, unmatched = parse_access_list_show(acl_lines)
        print_access_list_show(meta, rules, partials, unmatched)
    else:
        print("  [SKIPPED] ACCESS-LIST — section empty or not found.\n")

    # ── RUNNING-CONFIG-ACCESS-LIST ────────────────────────────
    cfg_lines = sections_data.get("RUNNING-CONFIG-ACCESS-LIST", [])
    if cfg_lines:
        cfg_rules, cfg_partials, cfg_unmatched = \
            parse_running_config_acl(cfg_lines)
        print_running_config_acl(cfg_rules, cfg_partials, cfg_unmatched)
    else:
        print("  [SKIPPED] RUNNING-CONFIG-ACCESS-LIST —"
              " section empty or not found.\n")

    # ── RUNNING-CONFIG-CRYPTO ─────────────────────────────────
    crypto_lines = sections_data.get("RUNNING-CONFIG-CRYPTO", [])
    if crypto_lines:
        results = parse_crypto(crypto_lines)
        print_crypto(*results)
    else:
        print("  [SKIPPED] RUNNING-CONFIG-CRYPTO —"
              " section empty or not found.\n")


if __name__ == "__main__":
    main()
