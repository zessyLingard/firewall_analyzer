#!/usr/bin/env python3
"""
core_models.py — Typed dataclass structures for firewall rules.

Provides:
    PortRange  — single port, range, or set; handles both iptables (20-25)
                 and nftables (20:25) formats.
    Rule       — one firewall rule with full protocol/address/state coverage.
    Chain      — ordered list of rules plus default policy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Optional


# ------------------------------------------------------------------ #
#  PortRange
# ------------------------------------------------------------------ #
@dataclass
class PortRange:
    """
    Represents a port or range.
    Handles: '22', '8000-8080', '20:25' (nftables colon format).
    """
    min_port: int
    max_port: int

    @classmethod
    def parse(cls, s: str) -> PortRange:
        s = s.strip()
        for sep in ("-", ":"):
            if sep in s:
                parts = s.split(sep, 1)
                try:
                    lo = int(parts[0])
                    hi = int(parts[1])
                    return cls(lo, hi)
                except (ValueError, IndexError):
                    pass
        try:
            return cls(int(s), int(s))
        except ValueError:
            return cls(0, 65535)

    def contains(self, port: int) -> bool:
        return self.min_port <= port <= self.max_port

    def __repr__(self) -> str:
        if self.min_port == self.max_port:
            return str(self.min_port)
        return f"{self.min_port}-{self.max_port}"


# ------------------------------------------------------------------ #
#  Rule
# ------------------------------------------------------------------ #
@dataclass
class Rule:
    """
    Single firewall rule.

    Fields mirror iptables/nftables concepts:
      action        — ACCEPT | DROP | REJECT | LOG | NOTRACK
      protocol      — tcp | udp | icmp | esp | ... (None = all)
      sources       — list of IPv4Network / IPv6Network
      destinations  — list of IPv4Network / IPv6Network
      ports         — destination ports (PortRange list)
      source_ports  — source ports (PortRange list)
      states        — NEW | ESTABLISHED | RELATED | INVALID (conntrack)
      is_negated    — rule uses ! (negation)
      has_comment   — comment / description present
      raw_line      — original rule text
      line_number   — source file line number
    """
    table: str = "filter"
    chain: str = ""
    action: str = "ACCEPT"
    in_interface: Optional[str] = None
    out_interface: Optional[str] = None
    sources: list[IPv4Network | IPv6Network] = field(default_factory=list)
    destinations: list[IPv4Network | IPv6Network] = field(default_factory=list)
    ports: list[PortRange] = field(default_factory=list)
    source_ports: list[PortRange] = field(default_factory=list)
    protocol: Optional[str] = None
    src_range: Optional[str] = None   # nftables inline range: "10.0.0.1-10.0.0.100"
    dst_range: Optional[str] = None
    states: list[str] = field(default_factory=list)
    is_negated: bool = False
    has_comment: bool = False
    raw_line: str = ""
    line_number: int = 0
    address_unknown: bool = False

    def __post_init__(self) -> None:
        """Keep parser uncertainty explicit without changing the public model."""
        source_values = list(self.sources)
        destination_values = list(self.destinations)
        self.address_unknown = self.address_unknown or any(
            value is None for value in (*source_values, *destination_values)
        )
        self.sources = [value for value in source_values if value is not None]
        self.destinations = [value for value in destination_values if value is not None]

    # ----- convenience helpers -----

    @staticmethod
    def _range_is_any(value: Optional[str]) -> bool | None:
        """Return whether an inline address range is any address.

        ``None`` means no range was supplied; ``False`` also covers malformed
        ranges so callers do not turn parser uncertainty into an open rule.
        """
        if not value:
            return None
        try:
            start_text, end_text = value.split("-", 1)
            start = IPv4Address(start_text.strip()) if "." in start_text else IPv6Address(start_text.strip())
            end = IPv4Address(end_text.strip()) if "." in end_text else IPv6Address(end_text.strip())
            if start.version != end.version or int(start) > int(end):
                return False
            maximum = (2 ** start.max_prefixlen) - 1
            return int(start) == 0 and int(end) == maximum
        except ValueError:
            return False

    def unrestricted_source(self) -> bool:
        """True if the rule accepts traffic from every source."""
        if self.address_unknown:
            return False
        range_is_any = self._range_is_any(self.src_range)
        if range_is_any is False:
            return False
        if range_is_any is True:
            return True
        any4 = IPv4Network("0.0.0.0/0")
        any6 = IPv6Network("::/0")
        if any4 in self.sources or any6 in self.sources:
            return True
        return all(s.prefixlen == 0 for s in self.sources)

    def unrestricted_dest(self) -> bool:
        """True if the rule accepts traffic to every destination."""
        if self.address_unknown:
            return False
        range_is_any = self._range_is_any(self.dst_range)
        if range_is_any is False:
            return False
        if range_is_any is True:
            return True
        any4 = IPv4Network("0.0.0.0/0")
        any6 = IPv6Network("::/0")
        if any4 in self.destinations or any6 in self.destinations:
            return True
        return all(d.prefixlen == 0 for d in self.destinations)

    def matches_port(self, port: int) -> bool:
        """Check if this rule matches the given destination port."""
        if not self.ports:
            return True   # implicit 0-65535
        return any(p.contains(port) for p in self.ports)

    def is_ssh_port(self) -> bool:
        """True if rule matches SSH port 22 (or any port when unspecified)."""
        for p in self.ports:
            if p.contains(22):
                return True
        return not self.ports   # no port restriction → matches all incl. 22

    def has_explicit_port_restriction(self) -> bool:
        """True if ports are explicitly specified (not implicit 0-65535)."""
        return bool(self.ports)

    def is_protocol_with_no_ports(self) -> bool:
        """True for protocols that have no port semantics."""
        p = (self.protocol or "").lower()
        return p in {
            "icmp", "icmpv6", "ipv6-icmp",
            "esp", "ah", "gre", "vrrp",
            "igmp", "ospf", "pim",
        }

    def is_tcp_or_udp(self) -> bool:
        return (self.protocol or "").lower() in ("tcp", "udp")


# ------------------------------------------------------------------ #
#  Chain
# ------------------------------------------------------------------ #
@dataclass
class Chain:
    """
    Firewall chain: ordered list of rules plus default policy.
    """
    table: str = "filter"
    name: str = ""
    default_policy: Optional[str] = None   # ACCEPT | DROP | REJECT
    rules: list[Rule] = field(default_factory=list)
    metadata: dict[str, object] = field(default_factory=dict)


# ------------------------------------------------------------------ #
#  Known high-risk ports (CIS Benchmarks / NIST SP 800-41)
# ------------------------------------------------------------------ #
DATABASE_PORTS  = {3306, 5432, 27017, 6379, 11211, 1433}
MGMT_PORTS      = {389, 636, 445, 139, 23, 161, 162, 3389, 2375, 2376}
HIGH_RISK_PORTS = DATABASE_PORTS | MGMT_PORTS
