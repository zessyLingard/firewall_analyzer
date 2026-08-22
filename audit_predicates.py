#!/usr/bin/env python3
"""
audit_predicates.py — Shared evaluation predicates for firewall audit checklists.

Works with both dataclass Rule objects (from any parser's Chain.rules) and
legacy dict representations (keys: 'chain', 'target', 'source', 'dest',
'dport', 'sport', 'state', 'proto', 'has_comment', 'is_negated',
'in_interface', 'out_interface').

Callable interface (accepts either type):
    has_dest_port_restriction(r)
    has_source_restriction(r)
    is_loopback_interface(r)
    protocol_has_no_ports(r)
    is_state_new_or_unrestricted(r)
    is_fully_open_input(r)
    is_fully_open_output(r)
    is_ssh_relevant(r)
    is_spoofable_sport_only_input(r)
    source_within_admin_range(r, admin_network)
    check_default_policy(policies, explicit_drops)
    has_established_related_catch_all(chain_rules)
"""

from __future__ import annotations

import ipaddress
from typing import Any, Union

# ------------------------------------------------------------------ #
#  Protocol groups
# ------------------------------------------------------------------ #

# No TCP/UDP port semantics (icmp, esp, ah, gre, vrrp …)
# Also includes 'ip' and 'ip6' — the bare nftables layer-3 keywords that
# match packets regardless of transport protocol (the actual transport
# protocol would appear as 'ip protocol icmp/tcp/udp', not captured in the
# 'proto' field by the nftables_parser dict layer).
PORTLESS_PROTOCOLS: frozenset[str] = frozenset({
    "icmp", "icmpv6", "ipv6-icmp", "esp", "ah", "gre", "vrrp",
    "igmp", "ospf", "pim",
    "ip", "ip6", "ipv4", "ipv6",
})

# Common ways of writing "any address"
UNRESTRICTED_ADDR_PATTERNS: frozenset[str] = frozenset({
    "0.0.0.0/0", "0.0.0.0/0.0.0.0", "0/0", "0.0.0.0",
    "::/0", "::", "any", "all",
})


# ------------------------------------------------------------------ #
#  Field accessors — support both dict and Rule
# ------------------------------------------------------------------ #

def _str(r: Any, key: str) -> str | None:
    v = getattr(r, key, None) if hasattr(r, key) else r.get(key) if isinstance(r, dict) else None
    if isinstance(v, str):
        return v
    if v is None:
        return None
    return str(v)          # IPv4Network, PortRange, etc.


def _proto(r: Any) -> str | None:
    """Protocol field — checks 'proto' (all parsers) then 'protocol'."""
    return _str(r, "proto") or _str(r, "protocol")


def _list(r: Any, key: str) -> list:
    v = getattr(r, key, None) if hasattr(r, key) else r.get(key) if isinstance(r, dict) else None
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


# ------------------------------------------------------------------ #
#  1.  has_dest_port_restriction
# ------------------------------------------------------------------ #
def has_dest_port_restriction(r: Any) -> bool:
    """True if rule restricts destination port (--dport / --dports)."""
    dport = _str(r, "dport")
    if dport:
        return True
    dports = _str(r, "dports")
    if dports:
        return True
    # PortRange dataclass path (from Chain model)
    ports = _list(r, "ports")
    if any(p.min_port != 0 or p.max_port != 65535 for p in ports):
        return True
    return False


# ------------------------------------------------------------------ #
#  2.  has_source_restriction
# ------------------------------------------------------------------ #
def has_source_restriction(r: Any) -> bool:
    """True if rule has explicit source address restriction (-s / --src-range)."""
    if _str(r, "source"):
        return True
    if _str(r, "src_range"):
        return True
    # IPv4Network/IPv6Network list path
    srcs = _list(r, "sources")
    if srcs:
        for s in srcs:
            # A non-0/0 network is a restriction
            try:
                net = ipaddress.ip_network(s, strict=False) if isinstance(s, str) else s
                if net.prefixlen > 0:
                    return True
            except (ValueError, AttributeError):
                pass
    return False


# ------------------------------------------------------------------ #
#  3.  is_loopback_interface
# ------------------------------------------------------------------ #
def is_loopback_interface(r: Any) -> bool:
    """True if rule applies only to loopback interface (-i lo / -o lo)."""
    iif = _str(r, "in_interface")
    oif = _str(r, "out_interface")
    if iif in ("lo", '"lo"', "*lo*"):
        return True
    if oif in ("lo", '"lo"', "*lo*"):
        return True
    return False


# ------------------------------------------------------------------ #
#  4.  protocol_has_no_ports
# ------------------------------------------------------------------ #
def protocol_has_no_ports(r: Any) -> bool:
    """
    True if protocol has no port concept (icmp, esp, ah, gre …).

    Also returns True for the bare nftables layer-3 keywords 'ip'/'ip6'
    which match all transport protocols — EXCEPT when the rule itself carries
    an explicit --dport/--sport restriction, in which case the rule is
    port-restricted regardless of the protocol field.
    """
    # Explicit port restriction overrides any protocol classification
    if _str(r, "dport") or _str(r, "dports"):
        return False
    if _str(r, "sport") or _str(r, "sports"):
        return False

    proto = _proto(r)
    if not proto:
        return False
    return proto.strip().lower() in PORTLESS_PROTOCOLS


# ------------------------------------------------------------------ #
#  5.  is_state_new_or_unrestricted
# ------------------------------------------------------------------ #
def is_state_new_or_unrestricted(r: Any) -> bool:
    """True if state is NEW or absent (implicitly matches NEW)."""
    state = _str(r, "state")
    if not state:
        return True
    states = [s.strip().upper() for s in state.split(",")]
    return "NEW" in states


# ------------------------------------------------------------------ #
#  6.  is_fully_open_input
# ------------------------------------------------------------------ #
def is_fully_open_input(r: Any) -> bool:
    """
    INPUT ACCEPT rule with unrestricted source (0.0.0.0/0), state NEW/
    unrestricted, and protocol that has ports — regardless of whether a
    port IS specified (the note in the checklist confirms this).
    """
    if _str(r, "chain") != "INPUT":
        return False
    if _str(r, "target") != "ACCEPT":
        return False
    if is_loopback_interface(r):
        return False
    if protocol_has_no_ports(r):
        return False
    if _str(r, "src_range"):
        return False
    if not is_unrestricted_address(r):
        return False
    return is_state_new_or_unrestricted(r)


# ------------------------------------------------------------------ #
#  7.  is_fully_open_output
# ------------------------------------------------------------------ #
def is_fully_open_output(r: Any) -> bool:
    """
    OUTPUT ACCEPT rule with unrestricted destination (0.0.0.0/0), state
    NEW/unrestricted, and protocol that has ports.
    """
    if _str(r, "chain") != "OUTPUT":
        return False
    if _str(r, "target") != "ACCEPT":
        return False
    if is_loopback_interface(r):
        return False
    if protocol_has_no_ports(r):
        return False
    if _str(r, "dst_range"):
        return False
    if not is_unrestricted_dest_address(r):
        return False
    return is_state_new_or_unrestricted(r)


# ------------------------------------------------------------------ #
#  8.  is_ssh_relevant
# ------------------------------------------------------------------ #
def is_ssh_relevant(r: Any) -> bool:
    """
    Rule is SSH-relevant when it lives in INPUT, ACCEPT target, not loopback,
    protocol is TCP-compatible, state is NEW/unrestricted, and either matches
    port 22 explicitly or has no port restriction at all.
    """
    if _str(r, "chain") != "INPUT":
        return False
    if _str(r, "target") != "ACCEPT":
        return False
    if is_loopback_interface(r):
        return False
    if not _is_tcp_compatible(r):
        return False
    if not is_state_new_or_unrestricted(r):
        return False

    # Has a port restriction?  Then it must match 22.
    if _has_any_port_restriction(r):
        return _matches_ssh_port(r)
    return True   # no port restriction → matches all including 22


def _is_tcp_compatible(r: Any) -> bool:
    proto = _proto(r)
    if not proto:
        return True
    return proto.strip().lower() in ("tcp", "all", "6")


def _has_any_port_restriction(r: Any) -> bool:
    for key in ("dport", "sport", "dports", "sports"):
        if _str(r, key):
            return True
    # PortRange dataclass path
    for p in _list(r, "ports"):
        if p.min_port != 0 or p.max_port != 65535:
            return True
    return False


def _matches_ssh_port(r: Any, ssh_port: str = "22") -> bool:
    for key in ("dport", "sport", "dports", "sports"):
        val = _str(r, key)
        if not val:
            continue
        for p in val.split(","):
            p = p.strip()
            if p == ssh_port or p.lower() == "ssh":
                return True
            if ":" in p:
                lo, hi = p.split(":", 1)
                if lo.isdigit() and hi.isdigit() and int(lo) <= int(ssh_port) <= int(hi):
                    return True
    # PortRange dataclass path
    for p in _list(r, "ports"):
        if p.contains(int(ssh_port)):
            return True
    return False


# ------------------------------------------------------------------ #
#  9.  is_spoofable_sport_only_input
# ------------------------------------------------------------------ #
def is_spoofable_sport_only_input(r: Any) -> bool:
    """
    INPUT ACCEPT rule that only specifies --sport (no --dport) and has no
    ESTABLISHED,RELATED state — the source port can be spoofed to reach
    any destination port on this host.
    """
    if _str(r, "chain") != "INPUT":
        return False
    if _str(r, "target") != "ACCEPT":
        return False
    has_sport = bool(_str(r, "sport")) or bool(_str(r, "sports"))
    if not has_sport:
        return False
    # Check PortRange dataclass path for source_ports
    if not _list(r, "source_ports"):
        return False
    if has_dest_port_restriction(r):
        return False
    state = _str(r, "state")
    if state:
        states = [s.strip().upper() for s in state.split(",")]
        if "ESTABLISHED" in states or "RELATED" in states:
            return False
    return True


# ------------------------------------------------------------------ #
#  10. source_within_admin_range
# ------------------------------------------------------------------ #
def source_within_admin_range(r: Any, admin_network: Any) -> bool:
    """
    True if the rule's source (or src_range) is strictly contained within
    admin_network (an ipaddress.IPv4Network or IPv6Network).
    """
    src_range = _str(r, "src_range")
    if src_range and "-" in src_range:
        start_str, end_str = src_range.split("-", 1)
        try:
            start_ip = ipaddress.ip_address(start_str.strip())
            end_ip = ipaddress.ip_address(end_str.strip())
            return start_ip in admin_network and end_ip in admin_network
        except ValueError:
            pass

    source = _str(r, "source")
    if not source:
        return False
    try:
        src_net = ipaddress.ip_network(source, strict=False)
    except ValueError:
        return False
    try:
        return src_net.subnet_of(admin_network)
    except TypeError:
        return False


# ------------------------------------------------------------------ #
#  11. check_default_policy
# ------------------------------------------------------------------ #
def check_default_policy(
    policies: dict[str, str],
    explicit_drops: dict[str, bool],
) -> tuple[bool, str]:
    """
    Returns (passed, reason).
    PASS if:
      a) INPUT == DROP/REJECT AND OUTPUT == DROP/REJECT
      b) explicit DROP/REJECT rule exists in both INPUT and OUTPUT
    """
    input_pol = policies.get("INPUT", "").upper()
    output_pol = policies.get("OUTPUT", "").upper()

    if input_pol in ("DROP", "REJECT") and output_pol in ("DROP", "REJECT"):
        return True, "Default policy INPUT/OUTPUT = DROP/REJECT"

    inp_drop = explicit_drops.get("INPUT", False)
    out_drop = explicit_drops.get("OUTPUT", False)
    if inp_drop and out_drop:
        return True, "Co rule tuong minh '-j DROP' / '-j REJECT' o ca INPUT va OUTPUT"

    return False, (
        f"INPUT policy={input_pol or 'NOT SET'}, "
        f"OUTPUT policy={output_pol or 'NOT SET'}, "
        f"INPUT co explicit DROP/REJECT={inp_drop}, "
        f"OUTPUT co explicit DROP/REJECT={out_drop}"
    )


# ------------------------------------------------------------------ #
#  12. has_established_related_catch_all
# ------------------------------------------------------------------ #
def has_established_related_catch_all(chain_rules: Any) -> bool:
    """
    True if the chain has at least one ACCEPT rule matching ESTABLISHED or
    RELATED state.
    """
    for r in chain_rules:
        if _str(r, "target") != "ACCEPT":
            continue
        state = _str(r, "state")
        if not state:
            continue
        states = [s.strip().upper() for s in state.split(",")]
        if "ESTABLISHED" in states or "RELATED" in states:
            return True
    return False


# ------------------------------------------------------------------ #
#  Helpers
# ------------------------------------------------------------------ #

def _is_nftables_set(s: str) -> bool:
    """True if s looks like nftables set syntax: { ... } with any address content."""
    s = s.strip()
    if not (s.startswith("{") and s.endswith("}")):
        return False
    inner = s[1:-1].strip()
    return bool(inner)


def is_unrestricted_address(r: Any) -> bool:
    """True if rule source address is unrestricted (0.0.0.0/0 or equivalent)."""
    source = _str(r, "source")
    if not source:
        return True   # absent = any
    a = source.strip()
    if a.lower() in UNRESTRICTED_ADDR_PATTERNS:
        return True
    # nftables set syntax — only unrestricted if it contains only unrestricted patterns
    if _is_nftables_set(a):
        return False
    try:
        net = ipaddress.ip_network(source, strict=False)
        if net.prefixlen == 0:
            return True
    except ValueError:
        pass
    return False


def is_unrestricted_dest_address(r: Any) -> bool:
    """True if rule destination address is unrestricted (0.0.0.0/0 or equivalent)."""
    dest = _str(r, "dest")
    if not dest:
        return True
    a = dest.strip()
    if a.lower() in UNRESTRICTED_ADDR_PATTERNS:
        return True
    # nftables set syntax — only unrestricted if it contains only unrestricted patterns
    if _is_nftables_set(a):
        return False
    try:
        net = ipaddress.ip_network(dest, strict=False)
        if net.prefixlen == 0:
            return True
    except ValueError:
        pass
    return False


def sport_has_any_port_restriction(r: Any) -> bool:
    """True if rule specifies source ports (--sport/--sports)."""
    return bool(_str(r, "sport")) or bool(_str(r, "sports"))


def is_unrestricted_protocol(r: Any) -> bool:
    """True if rule has no protocol restriction (-p all or absent)."""
    proto = _str(r, "protocol")
    return not proto or proto.strip().lower() in ("all", "any")
