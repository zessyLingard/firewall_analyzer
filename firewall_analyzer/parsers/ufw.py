#!/usr/bin/env python3
"""
ufw parser — parses ufw status/output into dict[str, Chain].

Handles:
  - ufw status numbered (verbose)
  - ufw status raw (numbered with rules as -A lines)
  - ufwconf / ufw.rules files
  - /etc/ufw/*.rules
"""

from __future__ import annotations

import ipaddress
import re

from firewall_analyzer.models import Chain, PortRange, Rule


def load_ufw(source: str | list[str]) -> dict[str, Chain]:
    """
    Parse a ufw file or output text into {chain_name: Chain}.

    Args:
        source: file path (str) or text (list[str] of lines)

    Returns:
        dict[str, Chain]
    """
    if isinstance(source, str):
        with open(source, encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    else:
        lines = source

    lines = [ln.rstrip("\n") for ln in lines]

    # Try to detect format
    text = "\n".join(lines)
    if "Status: active" in text or "Status: inactive" in text:
        return _parse_status_output(lines)
    if _is_iptables_style(lines):
        return _parse_iptables_style(lines)
    return _parse_rules_file(lines)


def _parse_status_output(lines: list[str]) -> dict[str, Chain]:
    """
    Parse 'ufw status numbered' output.
    Lines look like:
      [ 1] 22                       ALLOW IN    Anywhere
      [ 2] 22/tcp                   ALLOW IN    Anywhere (v6)
      [ 3] 80/tcp                   DENY IN     192.168.1.0/24
    """
    chains: dict[str, Chain] = {
        "INPUT": Chain(name="INPUT", table="filter", default_policy="DROP"),
        "OUTPUT": Chain(name="OUTPUT", table="filter", default_policy="ACCEPT"),
    }

    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue

        # Skip header lines
        if ln.startswith("Status:") or ln.startswith("--") or ln.startswith("To") or ln.startswith("---"):
            continue

        # Parse numbered rule: "[ 3] 80/tcp  DENY IN  192.168.1.0/24"
        m = re.match(r"\[\s*\d+\]\s+(\S+)(?:\s+(\S+))?\s+(ALLOW|DENY|LIMIT)\s+IN\s+(.*)", ln)
        if not m:
            # Also try: "[ 1] 22  ALLOW IN  Anywhere"
            m = re.match(r"\[\s*\d+\]\s+(\S+)\s+(ALLOW|DENY|LIMIT)\s+IN\s+(.*)", ln)
            if not m:
                continue
            port_str, action_raw, dest_info = m.group(1), m.group(2), m.group(3)
            proto = None
        else:
            port_str, proto, action_raw, dest_info = m.group(1), m.group(2), m.group(3), m.group(4)

        action = "DROP" if action_raw == "DENY" else "ACCEPT" if action_raw in ("ALLOW", "LIMIT") else "ACCEPT"

        # Parse port
        ports, rule_proto = _parse_ufw_port(port_str, proto)

        # Parse source
        srcs: list = []
        if "Anywhere (v6)" in dest_info or "anywhere (v6)" in dest_info.lower():
            srcs = [ipaddress.ip_network("::/0")]
        elif "Anywhere" in dest_info or "anywhere" in dest_info.lower():
            srcs = [ipaddress.ip_network("0.0.0.0/0")]
        else:
            # Try to extract CIDR
            cidr_m = re.search(r"(\S+/\d+)", dest_info)
            if cidr_m:
                srcs = [_safe_net(cidr_m.group(1))]
            else:
                host_m = re.search(r"([0-9a-fA-F:.]+)", dest_info)
                if host_m:
                    try:
                        address = ipaddress.ip_address(host_m.group(1))
                        prefix = 128 if address.version == 6 else 32
                        srcs = [ipaddress.ip_network(f"{address}/{prefix}")]
                    except ValueError:
                        srcs = [ipaddress.ip_network("0.0.0.0/0")]
                else:
                    srcs = [ipaddress.ip_network("0.0.0.0/0")]

        raw = ln
        chains["INPUT"].rules.append(Rule(
            table="filter",
            chain="INPUT",
            action=action,
            sources=srcs,
            ports=ports,
            protocol=rule_proto,
            raw_line=raw,
            has_comment=False,
        ))

    return chains


def _parse_ufw_port(port_str: str, proto: str | None) -> tuple[list[PortRange], str | None]:
    """
    Parse ufw port spec: '22', '22/tcp', '8000:8080', '8000:8080/tcp'.
    """
    rule_proto: str | None = None
    actual_port = port_str

    if "/" in port_str:
        actual_port, rule_proto = port_str.split("/", 1)
    elif proto:
        rule_proto = proto

    actual_port = actual_port.strip()
    if not actual_port:
        return [], rule_proto

    if ":" in actual_port:
        parts = actual_port.split(":", 1)
        try:
            lo = int(parts[0])
            hi = int(parts[1])
            return [PortRange(lo, hi)], rule_proto
        except ValueError:
            return [], rule_proto

    try:
        p = int(actual_port)
        return [PortRange(p, p)], rule_proto
    except ValueError:
        return [], rule_proto


def _is_iptables_style(lines: list[str]) -> bool:
    for ln in lines:
        ln = ln.strip()
        if ln.startswith("-A ") or ln.startswith("-I ") or ln.startswith(":INPUT "):
            return True
    return False


def _parse_iptables_style(lines: list[str]) -> dict[str, Chain]:
    """
    Parse ufw rules files that contain raw iptables commands.
    Lines look like:
      -A INPUT -j ACCEPT -p tcp --dport 22 -s 10.0.0.0/8
      -A ufw-user-input -j ACCEPT -p tcp --dport 80
    """
    chains: dict[str, Chain] = {}
    for ln in lines:
        ln = ln.strip()
        if not ln or ln.startswith("#") or ln.startswith("-N"):
            continue
        if not (ln.startswith("-A") or ln.startswith("-I")):
            continue

        rule = _parse_iptables_rule(ln)
        if rule is None:
            continue

        name = rule.chain or "INPUT"
        chains.setdefault(name, Chain(name=name, table="filter"))
        chains[name].rules.append(rule)

    return chains


def _parse_rules_file(lines: list[str]) -> dict[str, Chain]:
    """
    Parse /etc/ufw/*.rules files — mix of shell variables and iptables commands.
    """
    env: dict[str, str] = {}
    iptables_lines: list[str] = []
    in_iptables = False

    for ln in lines:
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue

        # Shell variable assignment
        m = re.match(r"^(\w+)=\s*(.+)$", ln)
        if m:
            env[m.group(1)] = m.group(2).strip()
            continue

        if ln.startswith("-A") or ln.startswith("-I") or ln.startswith("-P"):
            iptables_lines.append(ln)

    # Substitute env vars
    def subst(line: str) -> str:
        for k, v in env.items():
            line = re.sub(rf"\${k}\b", v, line)
            line = re.sub(rf"\${{{k}}}", v, line)
        return line

    chains: dict[str, Chain] = {}
    for ln in iptables_lines:
        rule = _parse_iptables_rule(subst(ln))
        if rule is None:
            continue
        name = rule.chain or "INPUT"
        chains.setdefault(name, Chain(name=name, table="filter"))
        chains[name].rules.append(rule)

    return chains


def _parse_iptables_rule(line: str) -> Rule | None:
    """Parse a single iptables-style -A/-I rule line."""
    import shlex
    tokens = shlex.split(line)
    if not tokens or tokens[0] not in ("-A", "-I"):
        return None

    chain = tokens[1]
    idx = 2
    if tokens[0] == "-I" and idx < len(tokens) and tokens[idx].isdigit():
        idx += 1

    src: list = []
    dst: list = []
    dports: list[PortRange] = []
    sports: list[PortRange] = []
    states: list[str] = []
    action = "ACCEPT"
    proto: str | None = None
    iif: str | None = None
    oif: str | None = None
    src_range: str | None = None
    dst_range: str | None = None
    has_comment = False

    while idx < len(tokens):
        tok = tokens[idx]
        if tok in ("-p", "--protocol"):
            proto = tokens[idx + 1]; idx += 2
        elif tok in ("-s", "--source"):
            src = [_safe_net(tokens[idx + 1])]; idx += 2
        elif tok in ("-d", "--destination"):
            dst = [_safe_net(tokens[idx + 1])]; idx += 2
        elif tok == "--dport":
            dports = [PortRange.parse(tokens[idx + 1])]; idx += 2
        elif tok == "--sport":
            sports = [PortRange.parse(tokens[idx + 1])]; idx += 2
        elif tok == "--dports":
            dports = [PortRange.parse(p) for p in tokens[idx + 1].split(",")]; idx += 2
        elif tok == "--sports":
            sports = [PortRange.parse(p) for p in tokens[idx + 1].split(",")]; idx += 2
        elif tok == "--src-range":
            src_range = tokens[idx + 1]; idx += 2
        elif tok == "--dst-range":
            dst_range = tokens[idx + 1]; idx += 2
        elif tok in ("-i", "--in-interface"):
            iif = tokens[idx + 1]; idx += 2
        elif tok in ("-o", "--out-interface"):
            oif = tokens[idx + 1]; idx += 2
        elif tok in ("--state", "--ctstate"):
            states = [s.strip() for s in tokens[idx + 1].split(",")]; idx += 2
        elif tok == "--comment":
            has_comment = True; idx += 2
        elif tok in ("-j", "--jump"):
            action = tokens[idx + 1].upper(); idx += 2
        else:
            idx += 1

    if not src:
        src = [ipaddress.ip_network("0.0.0.0/0")]
    if not dst:
        dst = [ipaddress.ip_network("0.0.0.0/0")]

    return Rule(
        table="filter",
        chain=chain,
        action=action,
        in_interface=iif,
        out_interface=oif,
        sources=src,
        destinations=dst,
        ports=dports,
        source_ports=sports,
        protocol=proto,
        states=states,
        has_comment=has_comment,
        raw_line=line,
        src_range=src_range,
        dst_range=dst_range,
    )


def _safe_net(addr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    try:
        return ipaddress.ip_network(addr.strip(), strict=False)
    except ValueError:
        return ipaddress.ip_network("0.0.0.0/0")
