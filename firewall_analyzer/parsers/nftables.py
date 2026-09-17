#!/usr/bin/env python3
"""
nftables parser — parses nftables list output into dict[str, Chain].
"""

from __future__ import annotations

import ipaddress
import re
import shlex

from firewall_analyzer.models import Chain, PortRange, Rule

_HOOK_MAP = {
    "hook input":    "INPUT",
    "hook output":   "OUTPUT",
    "hook forward":  "FORWARD",
    "hook prerouting":  "PREROUTING",
    "hook postrouting":  "POSTROUTING",
}


def load_nftables(source) -> dict[str, Chain]:
    """
    Parse an nftables list-format file or text into {chain_name: Chain}.

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

    chains: dict[str, Chain] = {}
    policies: dict[str, str] = {}
    cur_chain: str | None = None
    buf = ""
    depth = 0

    for raw in lines:
        depth += raw.count("{") - raw.count("}")
        ln = raw.strip()
        if not ln or ln.startswith("#"):
            continue

        if ln.startswith("table "):
            cur_chain = None
            depth = 0
            buf = ""
            continue

        if ln.startswith("chain "):
            if cur_chain and buf:
                _flush(buf, cur_chain, policies, chains)
                buf = ""
            hdr = ln.split()
            name = next(
                (m for h, m in _HOOK_MAP.items() if h in ln.lower()),
                hdr[1] if len(hdr) > 1 else "",
            )
            cur_chain = name.upper()
            chains.setdefault(cur_chain, Chain(table="filter", name=cur_chain))
            _extract_policy(ln, cur_chain, policies)
            continue

        if depth <= 0 or not cur_chain:
            continue

        _extract_policy(ln, cur_chain, policies)
        buf += " " + raw
        if buf.count("{") > buf.count("}"):
            continue

        _flush(buf, cur_chain, policies, chains)
        buf = ""

    if cur_chain and buf:
        _flush(buf, cur_chain, policies, chains)

    for name, pol in policies.items():
        if name in chains:
            chains[name].default_policy = pol.upper()

    return chains


def _extract_policy(line: str, chain: str, policies: dict[str, str]) -> None:
    for stmt in line.split(";"):
        stmt = stmt.strip().rstrip("{").strip()
        if stmt.startswith("policy "):
            tokens = stmt.split()
            if len(tokens) >= 2:
                policies[chain] = tokens[1].upper()


def _flush(buf: str, chain: str, policies: dict[str, str], chains: dict[str, Chain]) -> None:
    for stmt in buf.split(";"):
        stmt = stmt.strip()
        if not stmt or stmt.startswith("#"):
            continue
        # Skip inline policy declarations — they're stored as default_policy, not rules
        if stmt.startswith("policy "):
            continue
        if rule := _parse_stmt(stmt, chain):
            chains[chain].rules.append(rule)


def _parse_stmt(stmt: str, chain: str) -> Rule | None:
    src: list = []
    dst: list = []
    dports: list[PortRange] = []
    sports: list[PortRange] = []
    states: list[str] = []
    act = ""
    iif: str | None = None
    oif: str | None = None
    proto: str | None = None
    has_comment = False
    src_range: str | None = None
    dst_range: str | None = None

    tokens = list(shlex.shlex(stmt, posix=True))
    j = 0
    while j < len(tokens):
        tok = tokens[j].strip()

        if tok in ("accept", "drop", "reject", "log"):
            act = tok.upper(); j += 1; continue
        if tok == "notrack":
            act = "NOTRACK"; j += 1; continue

        if tok in ("ip", "ipv4"):
            proto = "ip"; j += 1; continue
        if tok in ("ip6", "ipv6"):
            proto = "ip6"; j += 1; continue

        if tok in ("saddr", "daddr") and j + 1 < len(tokens):
            quad_ip, next_i = _reassemble(tokens, j + 1)
            if quad_ip is not None:
                nets = _parse_addresses(quad_ip)
            else:
                val, next_i = _collect_value(tokens, j + 1)
                nets = _parse_addresses(val)
            if tok == "saddr":
                src.extend(nets)
            else:
                dst.extend(nets)
            j = next_i; continue

        if tok == "dport" and j + 1 < len(tokens):
            proto = proto or "tcp"
            val, next_i = _collect_value(tokens, j + 1)
            dports.extend(_parse_ports(val))
            j = next_i; continue

        if tok == "ct" and j + 1 < len(tokens) and tokens[j + 1].strip() == "state":
            val, next_i = _collect_value(tokens, j + 2)
            for s in val.upper().split(","):
                if s.strip():
                    states.append(s.strip())
            j = next_i; continue

        if tok in ("iif", "iifname") and j + 1 < len(tokens):
            iif = tokens[j + 1].strip().strip('"'); j += 2; continue
        if tok in ("oif", "oifname") and j + 1 < len(tokens):
            oif = tokens[j + 1].strip().strip('"'); j += 2; continue

        if tok in ("src", "dst") and j + 1 < len(tokens):
            val, next_i = _collect_value(tokens, j + 1)
            val = val.strip().strip('"')
            if "-" in val and not val.startswith("{"):
                if tok == "src":
                    src_range = val
                else:
                    dst_range = val
            j = next_i; continue

        if tok == "comment":
            has_comment = True; j += 1; continue

        j += 1

    if not act:
        return None
    if not src:
        src = [ipaddress.ip_network("0.0.0.0/0")]
    if not dst:
        dst = [ipaddress.ip_network("0.0.0.0/0")]

    return Rule(
        table="filter",
        chain=chain,
        action=act,
        in_interface=iif,
        out_interface=oif,
        sources=src,
        destinations=dst,
        ports=dports,
        source_ports=sports,
        states=states,
        is_negated=False,
        raw_line=stmt,
        has_comment=has_comment,
        protocol=proto,
        src_range=src_range,
        dst_range=dst_range,
    )


_KEYWORDS = frozenset({
    "accept", "drop", "reject", "log", "notrack",
    "ip", "ip6", "ipv4", "ipv6", "tcp", "udp", "icmp", "ct",
    "saddr", "daddr", "dport", "sport", "comment",
    "iif", "iifname", "oif", "oifname", "state",
})


def _collect_value(tokens: list[str], start: int) -> tuple[str, int]:
    brace_depth = 0
    end = start
    while end < len(tokens):
        t = tokens[end].strip()
        if t == "{": brace_depth += 1
        elif t == "}":
            if brace_depth == 0: break
            brace_depth -= 1
        if brace_depth == 0 and (t in _KEYWORDS or t in ("#",)):
            break
        end += 1
    return " ".join(tokens[start:end]).strip(), end


def _reassemble(tokens: list[str], start: int) -> tuple[str | None, int]:
    """Reassemble a dotted-quad IP that shlex split into fragments."""
    kw = frozenset({"accept", "drop", "reject", "log", "notrack",
                     "ip", "ip6", "ipv4", "ipv6", "tcp", "udp", "icmp", "ct",
                     "saddr", "daddr", "dport", "sport", "comment",
                     "iif", "iifname", "oif", "oifname", "state"})
    parts: list[str] = []
    i = start
    while i < len(tokens):
        t = tokens[i].strip()
        if t in kw or t.startswith("#") or t in ("{", "}", ","):
            break
        if not t:
            i += 1; continue
        parts.append(t)
        i += 1

    if len(parts) < 4:
        return None, start

    if parts[0] == "{":
        return None, start

    quad: list[str] = []
    for p in parts:
        pl = p.lower()
        if pl == "." or pl == "x" or p.replace(".", "").isdigit():
            quad.append(p)
        else:
            break

    if len(quad) < 4:
        return None, start

    filled = "".join("0" if s.lower() == "x" else s for s in quad)
    octets = filled.split(".")
    if len(octets) >= 4 and all(o.isdigit() for o in octets[:4]):
        try:
            ipaddress.IPv4Network(filled, strict=False)
            return filled, start + len(quad)
        except ValueError:
            pass
    return None, start


_REDACTED_PATTERNS = re.compile(r'^(\d+(?:\.[xX\d]+)*)$')


def _sanitise(raw: str) -> str:
    raw = raw.strip().strip('"').strip()
    raw = re.sub(r'\s+', '', raw)
    if not raw:
        return "0.0.0.0/0"
    if ":" in raw:
        return raw
    segs = raw.split(".")
    if len(segs) != 4:
        return "0.0.0.0/0"
    concrete = 0
    for s in segs:
        sl = s.lower()
        if sl == "x": break
        if not s[0].isdigit(): break
        concrete += 1
    if concrete == 0:
        return "0.0.0.0/0"
    concrete_str = ".".join(segs[:concrete])
    octets = concrete_str.split(".")
    while len(octets) < 4:
        octets.append("0")
    concrete_str = ".".join(octets)
    return f"{concrete_str}/{concrete * 8}"


def _parse_ports(val: str) -> list[PortRange]:
    val = val.strip().strip('"').strip()
    if not val:
        return []
    if val.startswith("{"):
        inner = val[1:-1]
        return [PortRange.parse(p.strip()) for p in inner.split(",") if p.strip()]
    return [PortRange.parse(val)]


def _parse_addresses(val: str) -> list:
    val = re.sub(r'\s+', ' ', val).strip('"').strip()
    if not val:
        return []
    if val.startswith("{"):
        inner = val[1:-1]
        results = []
        for part in inner.split(","):
            addr = _sanitise(re.sub(r'\s+', '', part.strip()))
            try:
                results.append(ipaddress.ip_network(addr, strict=False))
            except ValueError:
                pass
        return results
    addr = _sanitise(re.sub(r'\s+', '', val))
    try:
        return [ipaddress.ip_network(addr, strict=False)]
    except ValueError:
        return []
