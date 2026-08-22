#!/usr/bin/env python3
"""
nftables_parser.py — Bracket-depth state machine parser for nftables list output.

Handles:
  • table / chain / rule nesting via brace-count tracking (no regex)
  • Redacted/sanitised IPs: '192.x.x.x', '10.x.x.x' → valid placeholders
  • Anonymous sets: { 20, 21 }, { 443, 80 }
  • Inline handles: '# handle 12'
  • comment attributes: 'comment "..."'
  • hook → chain name mapping (hook input → INPUT, etc.)

Provides two interfaces:
  load_nftables(path) → dict[str, Chain]
      High-level: list of Chain objects with Rule dataclass instances.
  load_rules(path) → tuple[dict, dict, list]
      Legacy compatibility: (policies, rules_by_chain, all_rules)
      where each rule is a dict with keys matching audit_predicates.py.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from core_models import Chain, PortRange, Rule

_HOOK_MAP = {
    "hook input":    "INPUT",
    "hook output":   "OUTPUT",
    "hook forward":  "FORWARD",
    "hook prerouting":  "PREROUTING",
    "hook postrouting":  "POSTROUTING",
}

# Protocols that appear as bare keywords before saddr/daddr
_PROTO_KEYWORDS = frozenset({"ip", "ip6", "ipv4", "ipv6", "tcp", "udp", "icmp"})

# Redacted-address patterns that should not be passed to ipaddress.ip_network
# (e.g. '192.x.x.x', '10.x.x.0', '0.0.0.x').
_REDACTED_PATTERNS = re.compile(r'^(\d+(?:\.[xX\d]+)*)$')


# ======================================================================= #
#  Sanitisation
# ======================================================================= #

def _sanitise_address(raw: str) -> str:
    """
    Convert a potentially redacted/sanitised address string to a valid
    placeholder that won't crash ipaddress.ip_network.

    Handles both clean dotted-quad input ('192.x.x.x') and whitespace-stripped
    fragments from shlex ('192xxx' after re.sub(r'\\s+','',...) on '192 . x . x . x').

    '192.x.x.x' / '192xxx'        → '192.0.0.0/24'
    '192.x.x.0' / '192xx'        → '192.0.0.0/24'
    '192.168.x.1' / '192168x'    → '192.168.0.0/16'
    '10.0.0.x' / '1000x'         → '10.0.0.0/24'
    '0.0.0.x' / '0xxx'           → '0.0.0.0/0'
    '192.168.1.100'               → '192.168.1.100/32'
    Anything unrecognisable           → '0.0.0.0/0'
    """
    raw = raw.strip().strip('"').strip()
    # Collapse ALL whitespace before any processing — '192 . x . x . x' → '192xxx'
    raw = re.sub(r'\s+', '', raw)
    if not raw:
        return "0.0.0.0/0"

    # IPv6 — pass through; caller catches ValueError
    if ":" in raw:
        return raw

    # IPv4 — count how many concrete (non-'x') octets there are from the left
    # We must detect octet boundaries. Two cases:
    # 1. Normal dotted form: '192.x.x.x' → split on '.'
    # 2. Stripped form (shlex whitespace removed): '192xxx' → infer 1 octet of 3 digits
    #
    # Detect stripped form: no '.' present, only digits + 'x', leading chars are digits
    # Handle both '192xxx' and '192 xxx' (with internal spaces from shlex fragments)
    no_ws = re.sub(r'\s+', '', raw)         # '192 . x . x . x' → '192xxx'
    stripped = no_ws.replace("x", "").replace("X", "")
    is_stripped = ("." not in no_ws and
                   stripped.isdigit() and
                   len(stripped) > 0)

    if is_stripped:
        # Stripped dotted-quad: '192xxx' from collapsing '192 . x . x . x'.
        # Always reconstruct full dotted-quad form for ipaddress compatibility.
        leading_digits = ""
        for ch in raw:
            if ch.isdigit():
                leading_digits += ch
            else:
                break
        concrete = len(leading_digits) if leading_digits else 0
        if concrete == 0:
            return "0.0.0.0/0"
        # How many full octets do the leading digits cover?
        # 1-3 digits → 1 octet, 4-6 digits → 2 octets, etc.
        concrete_octets = min((concrete + 2) // 3, 4)
        # Fill remaining octets with '0'
        full = leading_digits
        while len(full) < 3 * concrete_octets:
            full += "0"
        octets = [full[i * 3 : i * 3 + 3].ljust(3, "0") for i in range(concrete_octets)]
        while len(octets) < 4:
            octets.append("000")
        concrete_str = ".".join(octets)
        cidr = concrete_octets * 8
        return f"{concrete_str}/24" if cidr < 32 else f"{concrete_str}/32"

    # Normal dotted form
    segs = raw.split(".")
    if len(segs) != 4:
        return "0.0.0.0/0"

    # Count concrete octets from the left.
    # An octet is concrete if:
    #   - its leading characters are all digits (possibly with trailing 'x')
    #     e.g. '192x' means '192.0.0.0/24' (prefix = 1 octet)
    #   - it is exactly 'x' or 'X' (fully redacted) — only counts after
    #     at least one concrete digit octet has been seen
    concrete = 0
    for s in segs:
        sl = s.lower()
        if sl == "x":
            break                        # first 'x' ends the prefix
        if not s[0].isdigit():
            break                        # keyword or garbage → stop
        # Starts with digits (maybe trailed by 'x'): concrete octet
        concrete += 1

    if concrete == 0:
        return "0.0.0.0/0"

    # Build a full 4-octet network address from the concrete octets
    # e.g. concrete=1 ('192.x.x.x') → '192.0.0.0'; concrete=2 ('192.168.x.x') → '192.168.0.0'
    concrete_str = ".".join(segs[:concrete])
    octets = concrete_str.split(".")
    while len(octets) < 4:
        octets.append("0")
    concrete_str = ".".join(octets)
    cidr = concrete * 8
    return f"{concrete_str}/{cidr}"


def _sanitise_port(raw: str) -> str:
    """
    Normalise a port token that may have been split by shlex.
    Handles single tokens like '20' or '443' that come from a set.
    Returns the raw token (already a single shlex token).
    """
    return raw.strip().strip('"')


# ======================================================================= #
#  Token-level helpers
# ======================================================================= #

def _collect_value(tokens: list[str], start: int) -> tuple[str, int]:
    """
    Consume tokens starting at `start` until a keyword or closing brace is
    encountered.  Handles nested '{ … }' sets correctly.

    Returns (joined_value, next_index).
    """
    kw = frozenset({
        "accept", "drop", "reject", "log", "notrack",
        "ip", "ip6", "ipv4", "ipv6", "tcp", "udp", "icmp", "ct",
        "saddr", "daddr", "dport", "sport", "comment",
        "iif", "iifname", "oif", "oifname", "state",
        "type", "priority", "policy", "flags",
    })
    brace_depth = 0
    end = start
    while end < len(tokens):
        t = tokens[end].strip()
        if t == "{":
            brace_depth += 1
        elif t == "}":
            if brace_depth == 0:
                break
            brace_depth -= 1
        if brace_depth == 0 and (t in kw or t in ("#",)):
            break
        end += 1
    joined = " ".join(tokens[start:end])
    return joined.strip(), end


def _reassemble_dotted_quad(tokens: list[str], start: int) -> tuple[str | None, int]:
    """
    Detect a dotted-quad address that shlex has fragmented into individual
    tokens ['192','.','x','.','x','.','x','tcp',...].

    Returns (reconstructed_ip_string, next_index) or (None, start) if not
    a dotted-quad pattern.
    """
    kw = frozenset({
        "accept", "drop", "reject", "log", "notrack",
        "ip", "ip6", "ipv4", "ipv6", "tcp", "udp", "icmp", "ct",
        "saddr", "daddr", "dport", "sport", "comment",
        "iif", "iifname", "oif", "oifname", "state",
    })

    # Collect consecutive non-keyword tokens into parts
    parts: list[str] = []
    i = start
    while i < len(tokens):
        t = tokens[i].strip()
        if t in kw or t.startswith("#") or t in ("{", "}", ","):
            break
        if not t:
            i += 1
            continue
        parts.append(t)
        i += 1

    if len(parts) < 4:
        return None, start

    # If the value starts with '{', it's a set — not a dotted-quad
    if parts[0] == "{":
        return None, start

    # Rebuild dotted-quad: dots, digits, and 'x' are part of the address;
    # any other token (including '}') terminates the sequence.
    quad: list[str] = []
    for p in parts:
        pl = p.lower()
        if pl == "." or pl == "x" or pl.replace(".", "").isdigit():
            quad.append(p)
        else:
            break

    if len(quad) < 4:
        return None, start

    # Replace every 'x' with '0' to get a concrete string for validation
    filled = "".join("0" if s.lower() == "x" else s for s in quad)
    octets = filled.split(".")
    if len(octets) >= 4 and all(o.isdigit() for o in octets[:4]):
        try:
            ipaddress.IPv4Network(filled, strict=False)
            consumed = len(quad)
            return filled, start + consumed
        except ValueError:
            pass

    return None, start


def _parse_ports(val: str) -> list[PortRange]:
    """
    Parse a port string (possibly a set '{ 20, 21 }' or a single '443')
    into a list of PortRange.
    """
    val = val.strip().strip('"').strip()
    if not val:
        return []
    if val.startswith("{"):
        inner = val[1:-1]
        results = []
        for part in inner.split(","):
            p = _sanitise_port(part.strip())
            if p:
                results.append(PortRange.parse(p))
        return results
    return [PortRange.parse(val)]


def _parse_addresses(val: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """
    Parse an address string (possibly a set '{ 10.0.0.1, 10.0.0.2 }')
    into a list of networks.  Redacted addresses are sanitised.

    Handles space-delimited fragments produced by shlex:
      '{ 192 . x . x . x , 192 . x . x . x }'
    """
    # Collapse whitespace inside '{ 192 . x . x . x , ... }' to single spaces;
    # _sanitise_address then handles the dots → '192.0.0.0/24' etc.
    val = re.sub(r'\s+', ' ', val).strip('"').strip()
    if not val:
        return []
    if val.startswith("{"):
        inner = val[1:-1]
        results = []
        for part in inner.split(","):
            # Remove all whitespace before passing to _sanitise_address so that
            # '192 . x . x . x' becomes '192.xxx' and dotted-quad detection works
            addr_raw = re.sub(r'\s+', '', part.strip())
            addr = _sanitise_address(addr_raw)
            if addr:
                try:
                    results.append(ipaddress.ip_network(addr, strict=False))
                except ValueError:
                    pass
        return results
    addr_raw = re.sub(r'\s+', '', val)
    addr = _sanitise_address(addr_raw)
    if not addr:
        return []
    try:
        return [ipaddress.ip_network(addr, strict=False)]
    except ValueError:
        return []


# ======================================================================= #
#  Core parser
# ======================================================================= #

def load_nftables(path: str) -> dict[str, Chain]:
    """
    Parse an nftables list-format file and return a dict of Chain objects.

    Handles brace-nesting, inline policies, comment attributes, handle
    comments, and redacted IP addresses.
    """
    chains: dict[str, Chain] = {}
    policies: dict[str, str] = {}
    cur_chain: str | None = None
    buf: str = ""
    depth: int = 0

    with open(path, encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    i = 0
    while i < len(lines):
        raw = lines[i].rstrip("\n")
        i += 1
        # Track brace depth
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
            # Finalise any pending chain body
            if cur_chain and buf:
                _flush_chain_buf(buf, cur_chain, policies, chains)
                buf = ""
            # Parse chain name from hook
            hdr = ln.split()
            name = next(
                (m for h, m in _HOOK_MAP.items() if h in ln.lower()),
                hdr[1] if len(hdr) > 1 else "",
            )
            cur_chain = name.upper()
            chains.setdefault(cur_chain, Chain(table="filter", name=cur_chain))
            _extract_policies(ln, cur_chain, policies)
            continue

        if depth <= 0 or not cur_chain:
            continue

        # Extract inline policies from any statement in the body
        _extract_policies(ln, cur_chain, policies)
        buf += " " + raw
        if buf.count("{") > buf.count("}"):
            continue

        # buf is a complete chain body
        _flush_chain_buf(buf, cur_chain, policies, chains)
        buf = ""

    # Finalise last chain
    if cur_chain and buf:
        _flush_chain_buf(buf, cur_chain, policies, chains)

    # Attach policies to chains
    for name, pol in policies.items():
        if name in chains:
            chains[name].default_policy = pol.upper()

    return chains


def _extract_policies(line: str, chain: str, policies: dict[str, str]) -> None:
    """Extract 'policy drop;' style statements from a line."""
    for stmt in line.split(";"):
        stmt = stmt.strip().rstrip("{").strip()
        if stmt.startswith("policy "):
            tokens = stmt.split()
            if len(tokens) >= 2:
                policies[chain] = tokens[1].upper()


def _flush_chain_buf(
    buf: str,
    chain: str,
    policies: dict[str, str],
    chains: dict[str, Chain],
) -> None:
    """
    Split a chain body on ';' and parse each statement as a rule.
    """
    for stmt in buf.split(";"):
        stmt = stmt.strip()
        if not stmt or stmt.startswith("#"):
            continue
        if rule := _parse_stmt(stmt, chain):
            chains[chain].rules.append(rule)


def _parse_stmt(stmt: str, chain: str, lineno: int = 0) -> Rule | None:
    """
    Parse a single nftables statement into a Rule dataclass.

    Handles:
      • 'accept' / 'drop' / 'reject' / 'log' / 'notrack' as action
      • 'ip saddr 10.0.0.1' or 'ip saddr { 10.0.0.1, 10.0.0.2 }'
      • 'tcp dport 22' or 'tcp dport { 20, 21 }'
      • 'ct state established,related'
      • 'iifname "lo"' / 'oifname "lo"'
      • 'comment "allow ssh"'
      • protocol keywords: ip, ip6, tcp, udp, icmp
    """
    src: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    dst: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    dports: list[PortRange] = []
    sports: list[PortRange] = []
    states: list[str] = []
    act = ""
    iif: str | None = None
    oif: str | None = None
    proto: str | None = None
    has_comment = False
    src_range_str: str | None = None
    dst_range_str: str | None = None

    tokens = list(shlex.shlex(stmt, posix=True))
    j = 0
    while j < len(tokens):
        tok = tokens[j].strip()
        consumed = 1   # how many tokens to advance

        # ---- Action ----
        if tok in ("accept", "drop", "reject", "log"):
            act = tok.upper(); j += 1; continue
        if tok == "notrack":
            act = "NOTRACK"; j += 1; continue

        # ---- Protocol (bare keyword, consumed only) ----
        if tok in ("ip", "ipv4"):
            proto = "ip"; j += 1; continue
        if tok in ("ip6", "ipv6"):
            proto = "ip6"; j += 1; continue

        # ---- saddr / daddr — may appear after any protocol ----
        if tok in ("saddr", "daddr") and j + 1 < len(tokens):
            # Try dotted-quad reassembly first
            quad_ip, next_i = _reassemble_dotted_quad(tokens, j + 1)
            if quad_ip is not None:
                nets = _parse_addresses(quad_ip)
            else:
                val, next_i = _collect_value(tokens, j + 1)
                nets = _parse_addresses(val)
            if tok == "saddr":
                src.extend(nets)
            else:
                dst.extend(nets)
            j = next_i
            continue

        # ---- dport (may appear after tcp/udp) ----
        if tok == "dport" and j + 1 < len(tokens):
            proto = proto or "tcp"
            val, next_i = _collect_value(tokens, j + 1)
            dports.extend(_parse_ports(val))
            j = next_i
            continue

        # ---- ct state ----
        if tok == "ct" and j + 1 < len(tokens) and tokens[j + 1].strip() == "state":
            val, next_i = _collect_value(tokens, j + 2)
            for s in val.upper().split(","):
                s = s.strip()
                if s:
                    states.append(s)
            j = next_i
            continue

        # ---- interface ----
        if tok in ("iif", "iifname") and j + 1 < len(tokens):
            iif = tokens[j + 1].strip().strip('"'); j += 2; continue
        if tok in ("oif", "oifname") and j + 1 < len(tokens):
            oif = tokens[j + 1].strip().strip('"'); j += 2; continue

        # ---- src / dst range (nftables inline range: 10.0.0.1-10.0.0.100) ----
        if tok in ("src", "dst") and j + 1 < len(tokens):
            val, next_i = _collect_value(tokens, j + 1)
            val = val.strip().strip('"')
            if "-" in val and not val.startswith("{"):
                if tok == "src":
                    src_range_str = val
                else:
                    dst_range_str = val
            j = next_i
            continue

        # ---- comment ----
        if tok == "comment":
            has_comment = True; j += 1; continue

        # Skip unknown token
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
        line_number=lineno,
        has_comment=has_comment,
        protocol=proto,
        src_range=src_range_str,
        dst_range=dst_range_str,
    )


# ======================================================================= #
#  Legacy compatibility layer
# ======================================================================= #

def load_rules(path: str) -> tuple[dict, dict, list]:
    """
    Return (policies, rules_by_chain, all_rules) where each rule is a dict
    with keys expected by audit_predicates.py.

    Dict shape per rule:
        chain, target, proto, source, dest, dport, dports, sport, sports,
        state, has_comment, is_negated, in_interface, out_interface, raw
    """
    chains = load_nftables(path)
    policies: dict[str, str] = {
        name: c.default_policy or ""
        for name, c in chains.items()
        if c.default_policy
    }
    rules_by_chain: dict[str, list[dict]] = {}
    all_rules: list[dict] = []

    def _ports_to_str(ports: list[PortRange]) -> str | None:
        if not ports:
            return None
        return ",".join(str(p) for p in ports)

    def _sources_to_str(srcs: list) -> str | None:
        if not srcs:
            return None
        return str(srcs[0])

    for name, chain in chains.items():
        rule_dicts: list[dict] = []
        for rule in chain.rules:
            rd: dict = {
                "chain":        rule.chain,
                "target":       rule.action,
                "proto":        rule.protocol,
                "source":       _sources_to_str(rule.sources),
                "dest":         _sources_to_str(rule.destinations),
                "dport":        _ports_to_str(rule.ports),
                "dports":       _ports_to_str(rule.ports),
                "sport":        _ports_to_str(rule.source_ports),
                "sports":       _ports_to_str(rule.source_ports),
                "state":        ",".join(rule.states) if rule.states else None,
                "has_comment":  rule.has_comment,
                "is_negated":   rule.is_negated,
                "in_interface": rule.in_interface,
                "out_interface": rule.out_interface,
                "src_range":    rule.src_range,
                "dst_range":    rule.dst_range,
                "raw":          rule.raw_line,
            }
            rule_dicts.append(rd)
            all_rules.append(rd)
        rules_by_chain[name] = rule_dicts

    return policies, rules_by_chain, all_rules
