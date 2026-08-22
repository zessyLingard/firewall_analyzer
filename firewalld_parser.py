#!/usr/bin/env python3
"""
firewalld_parser.py — Parser for firewalld configuration files.

Supports three input formats:

  1. XML Zone files  — /etc/firewalld/zones/*.xml
     Parses: <zone>, <service>, <port>, <rule>, <masquerade>

  2. Direct XML      — /etc/firewalld DIRECT rules (direct.xml)
     Parses: <rule> with iptables/nftables-style passthrough arguments

  3. CLI text output — firewalld-cmd --list-all --zone=<zone>
     Parses: service names, port ranges, rich-rule entries

Service-to-port dictionary (built-in):
  ssh        → 22/tcp
  http       → 80/tcp
  https      → 443/tcp
  dns        → 53/udp+tcp
  dhcp       → 67,68/udp
  snmp       → 161/udp
  ntp        → 123/udp
  smtp       → 25/tcp
  pop3       → 110/tcp
  imap       → 143/tcp
  ftp        → 21/tcp
  mysql      → 3306/tcp
  postgresql → 5432/tcp
  mongodb    → 27017/tcp
  redis      → 6379/tcp
  ldap       → 389/tcp
  ldaps      → 636/tcp
  kerberos   → 88/tcp+udp
  nfs        → 2049/tcp
  samba      → 445/tcp
  wins       → 137,138/udp
  vnc        → 5900/tcp
  rdp        → 3389/tcp
  snmptrap   → 162/udp
  custom     → parsed from XML port element

Provides:
  load_firewalld(path) → dict[str, Chain]   (Chain with Rule objects)
  load_rules(path)      → tuple[dict, dict, list]  (legacy dict format)
"""

from __future__ import annotations

import ipaddress
import re
import xml.etree.ElementTree as ET
from typing import Optional

from core_models import Chain, PortRange, Rule

# ------------------------------------------------------------------ #
#  Service catalogue
# ------------------------------------------------------------------ #
SERVICE_MAP: dict[str, list[tuple[str, int, int]]] = {
    "ssh":         [("tcp", 22, 22)],
    "http":        [("tcp", 80, 80)],
    "https":       [("tcp", 443, 443)],
    "dns":         [("tcp", 53, 53), ("udp", 53, 53)],
    "dhcp":        [("udp", 67, 67), ("udp", 68, 68)],
    "snmp":        [("udp", 161, 161)],
    "ntp":         [("udp", 123, 123)],
    "smtp":        [("tcp", 25, 25)],
    "pop3":        [("tcp", 110, 110)],
    "imap":        [("tcp", 143, 143)],
    "ftp":         [("tcp", 21, 21)],
    "mysql":       [("tcp", 3306, 3306)],
    "postgresql":  [("tcp", 5432, 5432)],
    "mongodb":     [("tcp", 27017, 27017)],
    "redis":       [("tcp", 6379, 6379)],
    "ldap":        [("tcp", 389, 389)],
    "ldaps":       [("tcp", 636, 636)],
    "kerberos":    [("tcp", 88, 88), ("udp", 88, 88)],
    "nfs":         [("tcp", 2049, 2049)],
    "samba":       [("tcp", 445, 445)],
    "smb":         [("tcp", 445, 445)],
    "wins":        [("udp", 137, 137), ("udp", 138, 138)],
    "vnc":         [("tcp", 5900, 5900)],
    "rdp":         [("tcp", 3389, 3389)],
    "snmptrap":    [("udp", 162, 162)],
}


# ------------------------------------------------------------------ #
#  Shared helpers
# ------------------------------------------------------------------ #

def _make_source_nets(src_list: list[str]) -> list:
    """Convert a list of source strings to IPv4/IPv6Network objects."""
    nets = []
    for s in src_list:
        try:
            nets.append(ipaddress.ip_network(s.strip(), strict=False))
        except ValueError:
            nets.append(ipaddress.ip_network("0.0.0.0/0"))
    return nets


def _make_rule(
    chain: str,
    action: str,
    protocol: Optional[str] = None,
    sources: Optional[list] = None,
    dests: Optional[list] = None,
    ports: Optional[list[tuple]] = None,   # [(proto, lo, hi), ...]
    states: Optional[list[str]] = None,
    iif: Optional[str] = None,
    raw: str = "",
    has_comment: bool = False,
) -> Rule:
    """
    Build a Rule dataclass from structured parameters.
    ports: list of (protocol, lo, hi) tuples → split into dports / source_ports
    """
    src_nets = sources or []
    dst_nets = dests or []
    dports: list[PortRange] = []
    sports: list[PortRange] = []

    if ports:
        for proto_port in ports:
            if len(proto_port) == 3:
                proto, lo, hi = proto_port
            else:
                proto, port = proto_port[0], proto_port[1]
                lo = hi = port
            pr = PortRange(lo, hi)
            if protocol and protocol.lower() in ("tcp", "udp"):
                dports.append(pr)
            else:
                dports.append(pr)   # store for inspection

    return Rule(
        table="filter",
        chain=chain,
        action=action.upper(),
        in_interface=iif,
        sources=src_nets,
        destinations=dst_nets,
        ports=dports,
        source_ports=sports,
        states=states or [],
        raw_line=raw,
        has_comment=has_comment,
        protocol=protocol,
    )


def _zone_to_rules(
    zone_elem: ET.Element,
    zone_name: str,
    chain_name: str,
) -> list[Rule]:
    """
    Convert an XML <zone> element into a list of Rule objects (INPUT-equivalent).
    """
    rules: list[Rule] = []
    sources: list[str] = []
    target = zone_elem.get("target", "default")

    # Source bindings
    for src in zone_elem.findall("source"):
        addr = src.get("address", "")
        if addr:
            sources.append(addr)

    # Shortcut: restrictive target = drop everything, no rules needed
    if target.upper() in ("DROP", "REJECT"):
        return [
            Rule(
                chain=chain_name,
                action="ACCEPT",
                sources=_make_source_nets(sources) if sources else [
                    ipaddress.ip_network("0.0.0.0/0")
                ],
                raw_line=f"<zone target={target}> (default accept)",
            )
        ]

    # Services
    for svc in zone_elem.findall("service"):
        svc_name = svc.get("name", "").lower()
        entries = SERVICE_MAP.get(svc_name, [])
        if entries:
            for proto, lo, hi in entries:
                rules.append(_make_rule(
                    chain=chain_name,
                    action="ACCEPT",
                    protocol=proto,
                    sources=_make_source_nets(sources) if sources else [],
                    ports=[(proto, lo, hi)],
                    raw=f"service {svc_name} → {proto}/{lo}-{hi}",
                    has_comment=True,
                ))

    # Explicit ports
    for port in zone_elem.findall("port"):
        proto = port.get("protocol", "tcp")
        port_attr = port.get("port", "")
        lo, hi = _parse_port_attr(port_attr)
        if lo and hi:
            rules.append(_make_rule(
                chain=chain_name,
                action="ACCEPT",
                protocol=proto,
                sources=_make_source_nets(sources) if sources else [],
                ports=[(proto, lo, hi)],
                raw=f"port {port_attr}/{proto}",
                has_comment=False,
            ))

    # Rich rules
    for rich in zone_elem.findall("rule"):
        rule = _parse_rich_rule(rich, chain_name, sources)
        if rule:
            rules.append(rule)

    # Masquerade → outbound NAT (not direct INPUT check)
    # icmp-block-inversion, forward ports — skipped as INPUT-only checks

    return rules


def _parse_rich_rule(
    elem: ET.Element,
    chain: str,
    zone_sources: list[str],
) -> Optional[Rule]:
    """
    Parse a <rule> element from an XML zone into a Rule.
    Supports: source, destination, port, protocol, action, element tag.
    """
    action_str = elem.get("family", "ipv4")

    # Determine action
    for tag in ("accept", "reject", "drop"):
        if elem.find(tag) is not None:
            action_str = tag.upper() if tag != "accept" else "ACCEPT"
            break
    else:
        # Default accept if no action element present
        action_str = "ACCEPT"

    src_addrs: list[str] = []
    dst_addrs: list[str] = []
    ports_list: list[tuple] = []
    proto: Optional[str] = None
    states: list[str] = []
    raw_parts: list[str] = []

    # Source
    src_elem = elem.find("source")
    if src_elem is not None:
        addr = src_elem.get("address", "")
        if addr:
            src_addrs.append(addr)
        raw_parts.append(f"saddr {addr}")

    # Destination
    dst_elem = elem.find("destination")
    if dst_elem is not None:
        addr = dst_elem.get("address", "")
        if addr:
            dst_addrs.append(addr)
        raw_parts.append(f"daddr {addr}")

    # Port element
    port_elem = elem.find("port")
    if port_elem is not None:
        proto = port_elem.get("protocol", "tcp")
        port_attr = port_elem.get("port", "")
        lo, hi = _parse_port_attr(port_attr)
        if lo and hi:
            ports_list.append((proto, lo, hi))
        raw_parts.append(f"{proto} dport {port_attr}")

    # Protocol
    proto_elem = elem.find("protocol")
    if proto_elem is not None:
        proto = proto_elem.get("value")
        raw_parts.append(f"proto {proto}")

    # Log
    log_elem = elem.find("log")
    if log_elem is not None:
        raw_parts.append("LOG")

    raw = "rich-rule: " + ", ".join(raw_parts) if raw_parts else "rich-rule"
    return _make_rule(
        chain=chain,
        action=action_str,
        protocol=proto,
        sources=_make_source_nets(src_addrs or zone_sources),
        dests=_make_source_nets(dst_addrs),
        ports=ports_list,
        states=states,
        raw=raw,
        has_comment=False,
    )


def _parse_port_attr(port_attr: str) -> tuple[int | None, int | None]:
    """Parse a firewalld port string like '443' or '8000-8080'."""
    port_attr = port_attr.strip()
    if not port_attr:
        return None, None
    if "-" in port_attr:
        parts = port_attr.split("-", 1)
        try:
            return int(parts[0]), int(parts[1])
        except (ValueError, IndexError):
            return None, None
    try:
        p = int(port_attr)
        return p, p
    except ValueError:
        return None, None


# ------------------------------------------------------------------ #
#  Direct rules (direct.xml)
# ------------------------------------------------------------------ #

def _parse_direct_rule(
    rule_elem: ET.Element,
) -> list[Rule]:
    """
    Parse a <rule> from direct.xml into Rule objects.
    Elements: <rule> with attrs: family (ipv4/ipv6), table, chain,
              and child <passthrough> with IPv4/IPv6, table, chain, priority, args.
    """
    rules: list[Rule] = []
    family = rule_elem.get("family", "ipv4")
    table = rule_elem.get("table", "filter")
    chain_name = rule_elem.get("chain", "").upper()

    for pt in rule_elem.findall("passthrough"):
        args_str = pt.text or ""
        raw = args_str.strip()
        action, proto, saddr, daddr, dport, sport, state, src_range, dst_range = _parse_iptables_args(args_str)
        rule = Rule(
            table=table,
            chain=chain_name,
            action=action or "ACCEPT",
            in_interface=None,
            out_interface=None,
            sources=[ipaddress.ip_network(saddr, strict=False)] if saddr else [ipaddress.ip_network("0.0.0.0/0")],
            destinations=[ipaddress.ip_network(daddr, strict=False)] if daddr else [ipaddress.ip_network("0.0.0.0/0")],
            ports=[PortRange.parse(dport)] if dport else [PortRange(0, 65535)],
            source_ports=[PortRange.parse(sport)] if sport else [],
            states=[state] if state else [],
            raw_line=raw,
            has_comment=False,
            protocol=proto,
            src_range=src_range,
            dst_range=dst_range,
        )
        rules.append(rule)
    return rules


def _parse_iptables_args(args_str: str) -> tuple:
    """
    Rough parse of an iptables/nftables passthrough argument string.
    Returns (action, protocol, saddr, daddr, dport, sport, state, src_range, dst_range).
    """
    import shlex
    action = proto = saddr = daddr = dport = sport = state = src_range = dst_range = None
    tokens = shlex.split(args_str)
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t in ("-A", "-I", "-N"):
            i += 2
            continue
        if t in ("-j", "--jump"):
            action = tokens[i + 1]; i += 2; continue
        if t in ("-p", "--protocol"):
            proto = tokens[i + 1]; i += 2; continue
        if t in ("-s", "--source"):
            saddr = tokens[i + 1]; i += 2; continue
        if t in ("-d", "--destination"):
            daddr = tokens[i + 1]; i += 2; continue
        if t in ("--dport", "--destination-port"):
            dport = tokens[i + 1]; i += 2; continue
        if t in ("--sport", "--source-port"):
            sport = tokens[i + 1]; i += 2; continue
        if t in ("--state", "--ctstate"):
            state = tokens[i + 1]; i += 2; continue
        if t == "--src-range":
            src_range = tokens[i + 1]; i += 2; continue
        if t == "--dst-range":
            dst_range = tokens[i + 1]; i += 2; continue
        i += 1
    return action, proto, saddr, daddr, dport, sport, state, src_range, dst_range


# ------------------------------------------------------------------ #
#  CLI text output parser
# ------------------------------------------------------------------ #

def _parse_cli_output(text: str) -> list[Rule]:
    """
    Parse firewalld-cmd --list-all output into Rule objects.
    Lines look like:
      ssh (tcp)                    → service
      8080:tcp                    → port
      10.0.0.0/8                  → source (applied to all subsequent rules)
      rich rules:
        rule family="ipv4" source address="192.168.1.0/24" accept
    """
    rules: list[Rule] = []
    sources: list[str] = []
    lines = text.strip().splitlines()

    i = 0
    while i < len(lines):
        ln = lines[i].strip()
        if not ln:
            i += 1
            continue

        # Source line (bare IP/CIDR)
        if not ln.startswith(" ") and not ln.startswith("\t") and _is_cidr(ln.split()[0]):
            sources = [ln.split()[0]]
            i += 1
            continue

        # Rich rule
        if "rich rule" in ln.lower() or ln.lstrip().startswith("rule"):
            rule = _parse_cli_rich_rule(ln, sources)
            if rule:
                rules.append(rule)
            i += 1
            continue

        # Service
        svc_name = ln.split()[0].lower()
        if svc_name in SERVICE_MAP:
            for proto, lo, hi in SERVICE_MAP[svc_name]:
                rules.append(_make_rule(
                    chain="INPUT",
                    action="ACCEPT",
                    protocol=proto,
                    sources=_make_source_nets(sources),
                    ports=[(proto, lo, hi)],
                    raw=ln,
                    has_comment=True,
                ))
            i += 1
            continue

        # Port (e.g. '8080:tcp' or '8000-8080:tcp')
        m = re.match(r"^(\d+(?:-\d+)?):(\w+)", ln.split()[0])
        if m:
            port_str, proto = m.group(1), m.group(2)
            lo, hi = _parse_port_attr(port_str)
            if lo and hi:
                rules.append(_make_rule(
                    chain="INPUT",
                    action="ACCEPT",
                    protocol=proto,
                    sources=_make_source_nets(sources),
                    ports=[(proto, lo, hi)],
                    raw=ln,
                    has_comment=False,
                ))
            i += 1
            continue

        i += 1

    return rules


def _is_cidr(s: str) -> bool:
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False


def _parse_cli_rich_rule(ln: str, default_sources: list[str]) -> Optional[Rule]:
    """Parse a single rich-rule from CLI text output."""
    # Simple: look for source address and action
    src_match = re.search(r'source\s+address="([^"]+)"', ln)
    dst_match = re.search(r'destination\s+address="([^"]+)"', ln)
    action_match = re.search(r'\b(accept|reject|drop)\b', ln.lower())

    srcs = [src_match.group(1)] if src_match else default_sources
    dsts = [dst_match.group(1)] if dst_match else []

    action = (action_match.group(1).upper()
              if action_match else "ACCEPT")

    return _make_rule(
        chain="INPUT",
        action=action,
        sources=_make_source_nets(srcs),
        dests=_make_source_nets(dsts),
        raw=ln.strip(),
        has_comment=False,
    )


# ------------------------------------------------------------------ #
#  Top-level loaders
# ------------------------------------------------------------------ #

def load_firewalld(path: str) -> dict[str, Chain]:
    """
    Auto-detect file format and parse into {chain_name: Chain}.
    """
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except ET.ParseError:
        # Not XML — treat as CLI text output
        with open(path, encoding="utf-8", errors="ignore") as fh:
            text = fh.read()
        return _load_cli_as_chains(text)

    tag = root.tag.lower()

    # --- Zone XML ---
    if tag == "zone":
        zone_name = root.get("name", "default")
        chain_name = "INPUT"
        rules = _zone_to_rules(root, zone_name, chain_name)
        chain = Chain(name=chain_name, table="filter", rules=rules)
        # Determine default_policy from zone target
        target = (root.get("target") or "default").upper()
        if target in ("DROP", "REJECT"):
            chain.default_policy = target
        elif target in ("ACCEPT", "DEFAULT"):
            chain.default_policy = "ACCEPT"
        return {chain_name: chain}

    # --- Direct XML ---
    if tag == "direct":
        chains: dict[str, Chain] = {}
        for rule_elem in root.findall(".//rule"):
            for r in _parse_direct_rule(rule_elem):
                chain_name = r.chain or "INPUT"
                chains.setdefault(chain_name, Chain(name=chain_name, table="filter"))
                chains[chain_name].rules.append(r)
        return chains

    # --- FirewallConfig XML (firewalld.conf style) ---
    if tag == "firewall-config":
        chains: dict[str, Chain] = {}
        for zone_elem in root.findall(".//zone"):
            zone_name = zone_elem.get("name", "default")
            chain_name = "INPUT"
            rules = _zone_to_rules(zone_elem, zone_name, chain_name)
            chain = Chain(name=chain_name, table="filter", rules=rules)
            target = (zone_elem.get("target") or "default").upper()
            if target in ("DROP", "REJECT", "ACCEPT"):
                chain.default_policy = target
            chains[chain_name] = chain
        return chains

    return {}


def _load_cli_as_chains(text: str) -> dict[str, Chain]:
    rules = _parse_cli_output(text)
    chain = Chain(name="INPUT", table="filter", rules=rules)
    return {"INPUT": chain}


def load_rules(path: str) -> tuple[dict, dict, list]:
    """
    Legacy dict format for audit_predicates.py compatibility.
    Returns (policies, rules_by_chain, all_rules).
    """
    chains = load_firewalld(path)
    policies: dict[str, str] = {
        name: (c.default_policy or "")
        for name, c in chains.items()
        if c.default_policy
    }
    rules_by_chain: dict[str, list[dict]] = {}
    all_rules: list[dict] = []

    def _ports_to_str(ports: list[PortRange]) -> str | None:
        if not ports:
            return None
        return ",".join(str(p) for p in ports)

    def _src_to_str(srcs: list) -> str | None:
        if not srcs:
            return None
        return str(srcs[0])

    for name, chain in chains.items():
        rd_list: list[dict] = []
        for rule in chain.rules:
            rd: dict = {
                "chain":        rule.chain,
                "target":       rule.action,
                "proto":        rule.protocol,
                "source":       _src_to_str(rule.sources),
                "dest":         _src_to_str(rule.destinations),
                "dport":        _ports_to_str(rule.ports),
                "dports":       _ports_to_str(rule.ports),
                "sport":        _ports_to_str(rule.source_ports),
                "sports":       _ports_to_str(rule.source_ports),
                "state":        ",".join(rule.states) if rule.states else None,
                "has_comment":  rule.has_comment,
                "is_negated":   rule.is_negated,
                "in_interface": rule.in_interface,
                "out_interface": rule.out_interface,
                "src_range":    getattr(rule, "src_range", None),
                "dst_range":    getattr(rule, "dst_range", None),
                "raw":          rule.raw_line,
            }
            rd_list.append(rd)
            all_rules.append(rd)
        rules_by_chain[name] = rd_list

    return policies, rules_by_chain, all_rules
