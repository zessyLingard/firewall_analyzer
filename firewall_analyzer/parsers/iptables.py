#!/usr/bin/env python3
"""
iptables parser — parses iptables-save format into dict[str, Chain].
"""

from __future__ import annotations

import ipaddress
import shlex

from firewall_analyzer.models import Chain, PortRange, Rule


def load_iptables(source: str | list[str]) -> dict[str, Chain]:
    """
    Parse an iptables-save file or text into {chain_name: Chain}.

    Args:
        source: file path (str) or rule text (list[str] of lines)

    Returns:
        dict[str, Chain]
    """
    if isinstance(source, str):
        with open(source, encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    else:
        lines = source

    policies: dict[str, str] = {}
    chains: dict[str, Chain] = {}
    in_filter = False

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue

        if line.startswith("*"):
            in_filter = line == "*filter"
            continue

        if not in_filter:
            continue

        if line == "COMMIT":
            in_filter = False
            continue

        if line.startswith(":"):
            parts = line.split()
            if len(parts) >= 2 and parts[1] != "-":
                policies[parts[0][1:]] = parts[1]
            continue

        if line.startswith("-P"):
            parts = line.split()
            if len(parts) >= 3:
                policies[parts[1]] = parts[2]
            continue

        if not (line.startswith("-A") or line.startswith("-I")):
            continue

        rule = _parse_rule_line(line)
        if rule is None:
            continue

        name = rule.chain
        if name not in chains:
            chains[name] = Chain(
                table="filter",
                name=name,
                default_policy=policies.get(name),
            )
        chains[name].rules.append(rule)

    # Attach policies
    for name, pol in policies.items():
        if name in chains and chains[name].default_policy is None:
            chains[name].default_policy = pol

    return chains


def _parse_rule_line(line: str) -> Rule | None:
    tokens = shlex.split(line)
    if not tokens or tokens[0] not in ("-A", "-I"):
        return None

    chain = tokens[1] if tokens[0] == "-A" else tokens[1]
    idx = 2
    if tokens[0] == "-I" and idx < len(tokens) and tokens[idx].isdigit():
        idx += 1

    src: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    dst: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
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
    is_negated = False

    while idx < len(tokens):
        tok = tokens[idx]
        if tok == "!":
            is_negated = True
            idx += 1
        elif tok in ("-p", "--protocol"):
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
        is_negated=is_negated,
        has_comment=has_comment,
        raw_line=line,
        src_range=src_range,
        dst_range=dst_range,
    )


def _safe_net(addr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    try:
        return ipaddress.ip_network(addr, strict=False)
    except ValueError:
        return ipaddress.ip_network("0.0.0.0/0")
