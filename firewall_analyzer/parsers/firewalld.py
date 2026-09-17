#!/usr/bin/env python3
"""
firewalld parser — parses firewalld XML zones, direct.xml, and CLI output
into dict[str, Chain].
"""

from __future__ import annotations

import ipaddress
import re
import xml.etree.ElementTree as ET

from firewall_analyzer.models import Chain, PortRange, Rule

SERVICE_MAP: dict[str, list[tuple]] = {
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
    "redis":       [("tcp", 6379, 6376)],
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


def load_firewalld(source) -> dict[str, Chain]:
    """
    Parse a firewalld file (XML or CLI text) into {chain_name: Chain}.

    Args:
        source: file path (str) or rule text (list[str] of lines)

    Returns:
        dict[str, Chain]
    """
    if isinstance(source, str):
        try:
            tree = ET.parse(source)
            root = tree.getroot()
        except ET.ParseError:
            with open(source, encoding="utf-8", errors="ignore") as f:
                text = f.read()
            return _parse_cli(text)
    else:
        text = "\n".join(source)
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return _parse_cli(text)

    tag = root.tag.lower()

    if tag == "zone":
        return _parse_zone_xml(root)
    if tag == "direct":
        return _parse_direct_xml(root)
    if tag == "firewall-config":
        return _parse_firewall_config(root)

    return {}


def _parse_zone_xml(root: ET.Element) -> dict[str, Chain]:
    zone_name = root.get("name", "default")
    chain_name = "INPUT"
    rules = _zone_rules(root, zone_name, chain_name)
    chain = Chain(name=chain_name, table="filter", rules=rules)
    target = (root.get("target") or "default").upper()
    if target in ("DROP", "REJECT", "ACCEPT"):
        chain.default_policy = target
    return {chain_name: chain}


def _parse_direct_xml(root: ET.Element) -> dict[str, Chain]:
    chains: dict[str, Chain] = {}
    for rule_elem in root.findall(".//rule"):
        for rule in _direct_rules(rule_elem):
            name = rule.chain or "INPUT"
            chains.setdefault(name, Chain(name=name, table="filter"))
            chains[name].rules.append(rule)
    return chains


def _parse_firewall_config(root: ET.Element) -> dict[str, Chain]:
    chains: dict[str, Chain] = {}
    for zone_elem in root.findall(".//zone"):
        zone_name = zone_elem.get("name", "default")
        rules = _zone_rules(zone_elem, zone_name, "INPUT")
        chain = Chain(name="INPUT", table="filter", rules=rules)
        target = (zone_elem.get("target") or "default").upper()
        if target in ("DROP", "REJECT", "ACCEPT"):
            chain.default_policy = target
        chains["INPUT"] = chain
    return chains


def _zone_rules(elem: ET.Element, zone_name: str, chain: str) -> list[Rule]:
    rules: list[Rule] = []
    sources: list[str] = []

    for src in elem.findall("source"):
        addr = src.get("address", "")
        if addr:
            sources.append(addr)

    target = elem.get("target", "default").upper()
    if target in ("DROP", "REJECT"):
        return [Rule(
            chain=chain,
            action="ACCEPT",
            sources=[_safe_net(s) for s in sources] or [ipaddress.ip_network("0.0.0.0/0")],
            raw_line=f"<zone target={target}>",
        )]

    for svc in elem.findall("service"):
        svc_name = svc.get("name", "").lower()
        entries = SERVICE_MAP.get(svc_name, [])
        for proto, lo, hi in entries:
            rules.append(_make_rule(
                chain=chain,
                action="ACCEPT",
                protocol=proto,
                sources=[_safe_net(s) for s in sources],
                ports=[(proto, lo, hi)],
                raw=f"service {svc_name} → {proto}/{lo}-{hi}",
                has_comment=True,
            ))

    for port in elem.findall("port"):
        proto = port.get("protocol", "tcp")
        attr = port.get("port", "")
        lo, hi = _parse_port_attr(attr)
        if lo and hi:
            rules.append(_make_rule(
                chain=chain,
                action="ACCEPT",
                protocol=proto,
                sources=[_safe_net(s) for s in sources],
                ports=[(proto, lo, hi)],
                raw=f"port {attr}/{proto}",
            ))

    for rich in elem.findall("rule"):
        rule = _rich_rule(rich, chain, sources)
        if rule:
            rules.append(rule)

    return rules


def _rich_rule(elem: ET.Element, chain: str, zone_sources: list[str]) -> Rule | None:
    action = "ACCEPT"
    for tag in ("accept", "reject", "drop"):
        if elem.find(tag) is not None:
            action = tag.upper() if tag != "accept" else "ACCEPT"
            break

    src_addrs: list[str] = []
    dst_addrs: list[str] = []
    ports_list: list[tuple] = []
    proto: str | None = None
    raw_parts: list[str] = []

    src_elem = elem.find("source")
    if src_elem is not None:
        addr = src_elem.get("address", "")
        if addr:
            src_addrs.append(addr)
            raw_parts.append(f"saddr {addr}")

    dst_elem = elem.find("destination")
    if dst_elem is not None:
        addr = dst_elem.get("address", "")
        if addr:
            dst_addrs.append(addr)
            raw_parts.append(f"daddr {addr}")

    port_elem = elem.find("port")
    if port_elem is not None:
        proto = port_elem.get("protocol", "tcp")
        attr = port_elem.get("port", "")
        lo, hi = _parse_port_attr(attr)
        if lo and hi:
            ports_list.append((proto, lo, hi))
        raw_parts.append(f"{proto} dport {attr}")

    proto_elem = elem.find("protocol")
    if proto_elem is not None:
        proto = proto_elem.get("value")
        raw_parts.append(f"proto {proto}")

    raw = "rich-rule: " + ", ".join(raw_parts) if raw_parts else "rich-rule"
    return _make_rule(
        chain=chain,
        action=action,
        protocol=proto,
        sources=[_safe_net(a) for a in (src_addrs or zone_sources)],
        dests=[_safe_net(a) for a in dst_addrs],
        ports=ports_list,
        raw=raw,
    )


def _direct_rules(rule_elem: ET.Element) -> list[Rule]:
    rules: list[Rule] = []
    chain_name = rule_elem.get("chain", "").upper()

    for pt in rule_elem.findall("passthrough"):
        args = (pt.text or "").strip()
        action, proto, saddr, daddr, dport, sport, state = _parse_iptables_args(args)
        rules.append(Rule(
            table=rule_elem.get("table", "filter"),
            chain=chain_name,
            action=(action or "ACCEPT").upper(),
            sources=[_safe_net(saddr)] if saddr else [ipaddress.ip_network("0.0.0.0/0")],
            destinations=[_safe_net(daddr)] if daddr else [ipaddress.ip_network("0.0.0.0/0")],
            ports=[PortRange.parse(dport)] if dport else [],
            source_ports=[PortRange.parse(sport)] if sport else [],
            states=[state] if state else [],
            raw_line=args,
            protocol=proto,
        ))
    return rules


def _parse_iptables_args(args_str: str):
    import shlex
    action = proto = saddr = daddr = dport = sport = state = None
    tokens = shlex.split(args_str)
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t in ("-A", "-I", "-N"): i += 2; continue
        if t in ("-j", "--jump"): action = tokens[i + 1]; i += 2; continue
        if t in ("-p", "--protocol"): proto = tokens[i + 1]; i += 2; continue
        if t in ("-s", "--source"): saddr = tokens[i + 1]; i += 2; continue
        if t in ("-d", "--destination"): daddr = tokens[i + 1]; i += 2; continue
        if t in ("--dport", "--destination-port"): dport = tokens[i + 1]; i += 2; continue
        if t in ("--sport", "--source-port"): sport = tokens[i + 1]; i += 2; continue
        if t in ("--state", "--ctstate"): state = tokens[i + 1]; i += 2; continue
        i += 1
    return action, proto, saddr, daddr, dport, sport, state


def _parse_cli(text: str) -> dict[str, Chain]:
    rules: list[Rule] = []
    sources: list[str] = []
    lines = text.strip().splitlines()
    i = 0

    while i < len(lines):
        ln = lines[i].strip()
        if not ln: i += 1; continue

        # Bare CIDR = source
        first = ln.split()[0] if ln.split() else ""
        if _is_cidr(first):
            sources = [first]
            i += 1; continue

        # Rich rule
        if "rich rule" in ln.lower() or ln.lstrip().startswith("rule"):
            rule = _cli_rich_rule(ln, sources)
            if rule:
                rules.append(rule)
            i += 1; continue

        # Service
        svc = ln.split()[0].lower()
        if svc in SERVICE_MAP:
            for proto, lo, hi in SERVICE_MAP[svc]:
                rules.append(_make_rule(
                    chain="INPUT",
                    action="ACCEPT",
                    protocol=proto,
                    sources=[_safe_net(s) for s in sources],
                    ports=[(proto, lo, hi)],
                    raw=ln,
                    has_comment=True,
                ))
            i += 1; continue

        # Port: "8080:tcp" or "8000-8080:udp"
        m = re.match(r"^(\d+(?:-\d+)?):(\w+)", ln.split()[0])
        if m:
            port_str, proto = m.group(1), m.group(2)
            lo, hi = _parse_port_attr(port_str)
            if lo and hi:
                rules.append(_make_rule(
                    chain="INPUT",
                    action="ACCEPT",
                    protocol=proto,
                    sources=[_safe_net(s) for s in sources],
                    ports=[(proto, lo, hi)],
                    raw=ln,
                ))
            i += 1; continue

        i += 1

    return {"INPUT": Chain(name="INPUT", table="filter", rules=rules)}


def _cli_rich_rule(ln: str, default_sources: list[str]) -> Rule | None:
    src_match = re.search(r'source\s+address="([^"]+)"', ln)
    dst_match = re.search(r'destination\s+address="([^"]+)"', ln)
    act_match = re.search(r'\b(accept|reject|drop)\b', ln.lower())

    srcs = [src_match.group(1)] if src_match else default_sources
    dsts = [dst_match.group(1)] if dst_match else []
    action = (act_match.group(1).upper() if act_match else "ACCEPT")

    return _make_rule(
        chain="INPUT",
        action=action,
        sources=[_safe_net(s) for s in srcs],
        dests=[_safe_net(d) for d in dsts],
        raw=ln.strip(),
    )


# ---- helpers ----

def _make_rule(
    chain: str,
    action: str,
    protocol: str | None = None,
    sources: list | None = None,
    dests: list | None = None,
    ports: list[tuple] | None = None,
    states: list[str] | None = None,
    iif: str | None = None,
    raw: str = "",
    has_comment: bool = False,
) -> Rule:
    dports: list[PortRange] = []
    sports: list[PortRange] = []
    if ports:
        for pp in ports:
            if len(pp) == 3:
                p, lo, hi = pp
            else:
                p, lo = pp[0], pp[1]
                hi = lo
            dports.append(PortRange(lo, hi))
    return Rule(
        table="filter",
        chain=chain,
        action=action.upper(),
        in_interface=iif,
        sources=(sources or []),
        destinations=(dests or []),
        ports=dports,
        source_ports=sports,
        states=(states or []),
        raw_line=raw,
        has_comment=has_comment,
        protocol=protocol,
    )


def _parse_port_attr(attr: str) -> tuple[int | None, int | None]:
    attr = attr.strip()
    if not attr:
        return None, None
    if "-" in attr:
        parts = attr.split("-", 1)
        try:
            return int(parts[0]), int(parts[1])
        except (ValueError, IndexError):
            return None, None
    try:
        p = int(attr)
        return p, p
    except ValueError:
        return None, None


def _safe_net(addr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    try:
        return ipaddress.ip_network(addr.strip(), strict=False)
    except ValueError:
        return ipaddress.ip_network("0.0.0.0/0")


def _is_cidr(s: str) -> bool:
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False
