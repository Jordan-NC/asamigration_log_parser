# ASA Migration Parser

A Python-based toolset for parsing Cisco ASA firewall configurations and generating structured migration analysis reports for ASA → Firepower Threat Defense (FTD) / Firepower Management Center (FMC) migrations.

Built by a Network Security Consultant to solve a real problem: manually reading through thousands of lines of ASA `show` command output before a migration is slow, error-prone, and easy to miss things. This toolset automates the analysis and produces two report formats — one for the engineer executing the migration, one for the customer or stakeholder.

---

## What This Does

- Parses structured ASA log files containing `show` command output
- Analyzes interfaces, routing, VPN sessions, ACLs, crypto/PKI, and NAT
- Flags migration blockers (inactive rules, unsupported algorithms, manual rebuild requirements)
- Assesses FTD compatibility per algorithm using Cisco's documented support matrix
- Generates a **Technical Report** for the migration engineer
- Generates an **Executive Report** for the customer / IT leadership

---

## Platform Coverage

| Technology | Commands Parsed |
|---|---|
| **Cisco ASA** | show version, show running-config all, show running-config, show interface ip brief, show access-list, show route, show vpn-sessiondb summary, show running-config crypto, show running-config access-list |
| **Target Platform** | Cisco Firepower Threat Defense (FTD) managed by FMC |

---

## Repository Structure

```
asa-migration-parser/
├── asa_parser_p1.py      # Phase 1: Section detection
├── asa_parser_p2.py      # Phase 2: Section extraction and content validation
├── asa_parser_p3.py      # Phase 3: Interface, route, VPN session parsing
├── asa_parser_p4.py      # Phase 4: ACL and crypto/PKI parsing
├── asa_parser_p5.py      # Phase 5: NAT parsing (Twice NAT + Object NAT)
├── asa_parser_p6.py      # Phase 6: Combined report generator
└── README.md
```

Each phase builds on the previous. Phases 1 and 2 validate your log file structure. Phases 3-5 parse specific sections. Phase 6 runs everything and generates the final reports.

---

## Prerequisites

- Python 3.8 or higher
- No external dependencies — standard library only (`re`, `os`, `sys`, `io`, `datetime`, `collections`)
- A structured ASA log file (see Log File Format below)

---

## Log File Format

The parser requires a single text file containing ASA `show` command output, with each command's output preceded by a section header in this exact format:

```
! ===SECTION: <SECTION-NAME>===
```

### Required Section Headers

```
! ===SECTION: RUNNING-CONFIG-ALL===
! ===SECTION: RUNNING-CONFIG===
! ===SECTION: INTERFACE===
! ===SECTION: INTERFACE-IP-BRIEF===
! ===SECTION: ACCESS-LIST===
! ===SECTION: ACCESS-LIST-ELEMENTS===
! ===SECTION: RUNNING-CONFIG-ACCESS-LIST===
! ===SECTION: ROUTE===
! ===SECTION: RUNNING-CONFIG-ROUTE===
! ===SECTION: RUNNING-CONFIG-CRYPTO===
! ===SECTION: RUNNING-CONFIG-IP-POOL===
! ===SECTION: VPN-SESSIONDB-SUMMARY===
! ===SECTION: VPN-SESSIONDB-ANYCONNECT===
! ===SECTION: CRYPTO-ISAKMP-SA===
! ===SECTION: CRYPTO-IPSEC-SA===
! ===SECTION: SERVICE-POLICY===
! ===SECTION: RUNNING-CONFIG-LOGGING===
! ===SECTION: LOGGING===
! ===SECTION: RUNNING-CONFIG-AAA===
! ===SECTION: RUNNING-CONFIG-AAA-SERVER===
```

### Example Log File Structure

```
! ===SECTION: INTERFACE-IP-BRIEF===
Interface                IP-Address      OK? Method Status                Protocol
GigabitEthernet0/0       10.0.0.1        YES CONFIG up                    up
GigabitEthernet0/1       192.168.1.1     YES CONFIG up                    up
Management0/0            unassigned      YES unset  up                    up

! ===SECTION: ROUTE===
S*       0.0.0.0 0.0.0.0 [1/0] via 10.0.0.254, outside
C        10.0.0.0 255.255.255.0 is directly connected, outside
C        192.168.1.0 255.255.255.0 is directly connected, inside

! ===SECTION: RUNNING-CONFIG-CRYPTO===
crypto ipsec ikev1 transform-set ESP-AES256-SHA esp-aes-256 esp-sha-hmac
crypto ikev1 enable outside
...
```

### Recommended Show Commands

Run these commands on the ASA primary unit (confirmed active in HA pair) and paste output under the corresponding section header:

```
show version
show failover
show running-config all
show running-config
show interface
show interface ip brief
show access-list
show access-list | include elements
show running-config access-list
show route
show running-config route
show running-config crypto
show running-config ip local pool
show vpn-sessiondb summary
show vpn-sessiondb anyconnect
show crypto isakmp sa
show crypto ipsec sa
show service-policy
show running-config logging
show logging
show running-config aaa
show running-config aaa-server
```

> **Security Note:** This log file will contain sensitive configuration data including interface IPs, ACL rules, VPN peer addresses, and tunnel group names. Handle it accordingly. Do not commit real customer log files to version control.

---

## Usage

### Step 1 — Validate your log file structure (optional but recommended)

```bash
python3 asa_parser_p1.py asa_logs.txt
python3 asa_parser_p2.py asa_logs.txt
```

Phase 1 confirms all section headers are detected. Phase 2 confirms content exists under each header and shows a preview of each section.

### Step 2 — Run individual parsers

```bash
python3 asa_parser_p3.py asa_logs.txt   # Interfaces, routes, VPN sessions
python3 asa_parser_p4.py asa_logs.txt   # ACLs, crypto, PKI
python3 asa_parser_p5.py asa_logs.txt   # NAT rules and network objects
```

### Step 3 — Generate the full migration reports

```bash
python3 asa_parser_p6.py asa_logs.txt
```

This runs all parsers and writes two files to the same directory as your log file:

```
asa_migration_technical.txt   ← For the migration engineer
asa_migration_executive.txt   ← For the customer / IT leadership
```

---

## Report Descriptions

### Technical Report

Organized into eight sections:

1. **Platform & Version** — ASA version, model, serial number, hostname
2. **Interface Inventory** — All interfaces with IP, status, protocol, and flags for down/admin-down/unassigned
3. **Routing Table** — Routes grouped by type (Connected, Static, OSPF, BGP, etc.) with default route callout and dynamic routing migration notes
4. **VPN Session Summary** — Active session counts by type (AnyConnect, IKEv1, IKEv2, Site-to-Site) with migration notes per type
5. **ACL Analysis** — Per-ACL rule counts, zero-hit rules, inactive rules, time-range rules, FQDN rules, logging level breakdown, object references, protocol inventory
6. **Crypto & PKI Analysis** — IKEv1/IKEv2 Phase 1 policies, transform sets, IPsec proposals, dynamic maps, static crypto maps, IPsec profiles, PKI trustpoints, certificate chains, RA VPN trustpoint, FTD compatibility per algorithm
7. **NAT Analysis** — Twice NAT rules with interface pair inventory, Object NAT rules, interface PAT identification, network object inventory, NAT-referenced objects by description
8. **Technical Migration Checklist** — Ordered numbered checklist: Pre-migration → Cleanup → PKI → VPN → NAT → Post-migration validation

### Executive Report

Organized into six sections written in plain business language — no CLI syntax:

1. **Executive Summary** — Overall migration risk rating (LOW / MEDIUM / MEDIUM-HIGH / HIGH) derived from actual parsed findings
2. **What We Found** — Plain-language description of network interfaces, firewall rules, VPN connectivity, NAT operations, and certificates
3. **Migration Risks and Business Impact** — HIGH and MEDIUM risk items with "What it means" and "Required action" for each
4. **Migration Effort Estimate** — Hour range estimates broken down by task category
5. **Pre-Migration Requirements** — Numbered checklist of items that must be completed before scheduling the cutover window
6. **Recommendations** — Actionable guidance tailored to what was actually found in the configuration

---

## FTD Algorithm Compatibility

The crypto parser flags every algorithm against Cisco's documented FTD support matrix (FMC Configuration Guide 6.7+ / ASA 9.13/9.15 release notes):

| Status | Meaning |
|---|---|
| `[OK]` | Supported on FTD |
| `[DEPRECATED]` | Functions but flagged for removal in future FTD versions |
| `[REMOVED]` | Not supported on FTD — will cause failure post-migration |

### Algorithms Flagged as REMOVED

| Category | Algorithms |
|---|---|
| Encryption | DES, 3DES |
| Integrity/Hash | MD5 |
| DH Groups | Group 1, Group 2, Group 24 |

### Algorithms Flagged as DEPRECATED

| Category | Algorithms |
|---|---|
| Encryption | (none currently) |
| Integrity/Hash | SHA-1 / SHA (160-bit) |
| DH Groups | Group 5 (deprecated for IKEv1, removed for IKEv2) |

---

## Three-Layer Parsing Architecture

Phases 4 and 5 use a three-layer parsing architecture to ensure nothing is silently dropped:

- **Layer 1 — Full match:** Built against the complete Cisco ASA documented syntax for each command. Every known syntax variant is covered.
- **Layer 2 — Partial match:** Lines that look relevant but don't fully match a known pattern are captured and flagged `[PARTIAL]` in the report. You know exactly what wasn't fully parsed.
- **Layer 3 — Unmatched capture:** Every remaining line in a NAT or crypto context that matches no pattern appears in an `[UNMATCHED]` section. Nothing is silently ignored.

---

## Known Limitations

- **NAT**: Twice NAT source is parsed fully. Very complex inline service clause variations may land in partial matches — review the UNMATCHED section in Phase 5 output.
- **Crypto**: `crypto ca` certificate chain content (base64 data) is intentionally not stored — only presence and serial numbers are captured. This is by design to avoid storing sensitive key material.
- **Version-specific output**: ASA output formatting varies between OS versions (9.8 through 9.18+). The parser is built against documented syntax but edge cases in specific version output may produce partial matches.
- **Non-standard configs**: Configurations using undocumented or deprecated ASA features may not parse cleanly. The partial/unmatched layers will surface these for manual review.
- **Phase 6 dependency**: Phase 6 imports Phases 3, 4, and 5 directly. All four files must be in the same directory.

---

## Use Cases

This toolset was built for the following real-world scenarios:

- **Pre-migration analysis** — Understand the full scope of an ASA config before starting a migration engagement
- **Migration risk assessment** — Identify blockers (inactive rules, unsupported crypto, manual rebuild requirements) before scheduling the cutover window
- **Customer reporting** — Deliver a professionally formatted executive summary to the customer or their IT leadership
- **Policy cleanup** — Identify zero-hit rules, inactive rules, and stale NAT entries that should be removed before migration
- **VPN audit** — Inventory all crypto algorithms across transform sets, IKEv1/IKEv2 policies, and IPsec proposals with FTD compatibility status
- **PKI documentation** — Inventory all trustpoints, certificate chains, and RA VPN certificate dependencies

---

## Extending This Toolset

The parse functions in each phase module are independent and importable. To add a new parser or extend an existing one:

1. Add regex patterns following the naming convention `RE_<THING>_<DESCRIPTOR>`
2. Add the parse function following the `parse_<section>` naming convention
3. Return structured dicts — avoid raw strings where possible
4. Add the corresponding print function following `print_<section>`
5. Import and call from Phase 6 via `run_all_parsers()`

Future phases planned:

- **Phase 7** — CLI argument support (`--section`, `--output`, `--format csv`)
- **Fortinet FortiGate parser** — Same architecture, FortiOS config format
- **Zscaler ZIA/ZPA export parser** — For Zscaler migration analysis
- **Azure NSG parser** — For cloud security migration documentation

---

## Author

Built by a Network Security Consultant specializing in enterprise firewall migrations, Zscaler SASE deployments, and security automation.

Core technologies: Cisco ASA / FTD / FMC, Fortinet FortiGate / FortiManager, Zscaler ZIA / ZPA / ZDX, Okta, Microsoft Entra ID, Python, Azure.

---

## Disclaimer

This toolset is provided for professional use in authorized migration engagements. It reads configuration data — it does not connect to any device, modify any configuration, or transmit any data. All processing is local.

Always validate parser output against the source configuration before using findings to drive migration decisions. This toolset assists analysis — it does not replace engineering judgment.

Do not commit customer log files or configuration data to version control.
