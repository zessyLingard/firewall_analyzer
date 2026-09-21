#!/usr/bin/env python3
"""
firewall_analyzer.analyzer — unified 10-point security audit.

Accepts dict[str, Chain] (from any parser) and returns AuditResult.

Checks:
  1.   Default INPUT/OUTPUT policy
  1c.  Missing ESTABLISHED,RELATED catch-all
  2a.  SSH rule missing comment
  2b.  SSH rule with unrestricted source
  3a.  INPUT ACCEPT with no destination port restriction
  3b.  OUTPUT ACCEPT with no destination port restriction
  4a.  INPUT fully open (unrestricted source + NEW state)
  4b.  OUTPUT fully open (unrestricted dest + NEW state)
  5.   SSH source outside admin CIDR
  6.   INPUT sport-only rule without ESTABLISHED,RELATED
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from collections.abc import Mapping
from ipaddress import IPv4Network, IPv6Network
from typing import Any, cast

from firewall_analyzer.models import Chain, PortRange, Rule


# --------------------------------------------------------------------------- #
#  Helpers
# --------------------------------------------------------------------------- #

def _value(r: object, key: str) -> object | None:
    if isinstance(r, Mapping):
        return cast(Mapping[str, object], r).get(key)
    return getattr(r, key, None)


def _str(r: object, key: str) -> str | None:
    v = _value(r, key)
    if isinstance(v, str):
        return v
    if v is None and key == "state":
        # Rule dataclass uses "states" (list), dict uses "state" (str)
        v = _value(r, "states")
        if isinstance(v, list):
            return ",".join(str(s) for s in cast(list[object], v)) if v else None
    if v is None:
        return None
    return str(v)


def _list(r: object, key: str) -> list[object]:
    v = _value(r, key)
    if v is None:
        return []
    if isinstance(v, list):
        return cast(list[object], v)
    return [v]


def _is_unrestricted_source(r: Any) -> bool:
    srcs = _list(r, "sources")
    if not srcs:
        return True
    for s in srcs:
        try:
            net = ipaddress.ip_network(s, strict=False) if isinstance(s, str) else s
            if isinstance(net, (IPv4Network, IPv6Network)) and net.prefixlen > 0:
                return False
        except (ValueError, AttributeError):
            pass
    return True


def _is_unrestricted_dest(r: Any) -> bool:
    dsts = _list(r, "destinations")
    if not dsts:
        return True
    for d in dsts:
        try:
            net = ipaddress.ip_network(d, strict=False) if isinstance(d, str) else d
            if isinstance(net, (IPv4Network, IPv6Network)) and net.prefixlen > 0:
                return False
        except (ValueError, AttributeError):
            pass
    return True


def _has_dest_port(r: Any) -> bool:
    if _str(r, "dport") or _str(r, "dports"):
        return True
    for p in _list(r, "ports"):
        if isinstance(p, PortRange) and (p.min_port != 0 or p.max_port != 65535):
            return True
    return False


def _has_source_port(r: Any) -> bool:
    if _str(r, "sport") or _str(r, "sports"):
        return True
    return bool(_list(r, "source_ports"))


def _is_loopback(r: Any) -> bool:
    return _str(r, "in_interface") in ("lo", '"lo"') or _str(r, "out_interface") in ("lo", '"lo"')


def _proto(r: Any) -> str | None:
    return _str(r, "protocol") or _str(r, "proto")


_PORTLESS = frozenset({"icmp", "icmpv6", "ipv6-icmp", "esp", "ah", "gre", "vrrp",
                         "igmp", "ospf", "pim", "ip", "ip6", "ipv4", "ipv6"})


def _proto_has_no_ports(r: Any) -> bool:
    if _str(r, "dport") or _str(r, "dports") or _str(r, "sport") or _str(r, "sports"):
        return False
    p = _proto(r)
    return bool(p and p.strip().lower() in _PORTLESS)

def _is_fully_open_accept(r: Any, direction: str) -> bool:
    """True when an ACCEPT rule has an unrestricted source or destination."""
    if _str(r, "action") != "ACCEPT" and _str(r, "target") != "ACCEPT":
        return False
    if _is_loopback(r):
        return False
    if direction == "INPUT" and _str(r, "chain") in ("OUTPUT", "FORWARD"):
        return False
    if direction == "OUTPUT" and _str(r, "chain") != "OUTPUT":
        return False
    if direction == "INPUT":
        if _str(r, "src_range") or not _is_unrestricted_source(r):
            return False
    elif direction == "OUTPUT":
        if _str(r, "dst_range") or not _is_unrestricted_dest(r):
            return False
    return _is_state_new(r) and not _is_estab_related_only(r)


def _is_estab_related_only(r: Any) -> bool:
    """True if rule ONLY matches ESTABLISHED/RELATED (no NEW state)."""
    state = _str(r, "state")
    if not state:
        return False
    states = [s.strip().upper() for s in state.split(",")]
    return "ESTABLISHED" in states or "RELATED" in states


def _is_state_new(r: Any) -> bool:
    state = _str(r, "state")
    if not state:
        return True
    return "NEW" in [s.strip().upper() for s in state.split(",")]


def _is_ssh_relevant(r: Any) -> bool:
    if _str(r, "chain") in ("OUTPUT", "FORWARD"):
        return False
    if _str(r, "action") != "ACCEPT" and _str(r, "target") != "ACCEPT":
        return False
    if _is_loopback(r):
        return False
    p = _proto(r)
    if p and p.strip().lower() not in ("tcp", "all", "6"):
        return False
    # Exclude ESTABLISHED,RELATED-only rules — they only permit return traffic
    if _is_estab_related_only(r):
        return False
    if not _is_state_new(r):
        return False

    if _has_dest_port(r):
        return _matches_ssh_port(r)
    return True


def _matches_ssh_port(r: Any) -> bool:
    for key in ("dport", "sport", "dports", "sports"):
        val = _str(r, key)
        if not val:
            continue
        for p in val.split(","):
            p = p.strip()
            if p in ("22", "ssh"):
                return True
            if ":" in p:
                parts = p.split(":", 1)
                if parts[0].isdigit() and parts[1].isdigit():
                    if int(parts[0]) <= 22 <= int(parts[1]):
                        return True
    for p in _list(r, "ports"):
        if isinstance(p, PortRange) and p.contains(22):
            return True
    return False


def _is_spoofable_sport_only(r: Any) -> bool:
    if _str(r, "chain") in ("OUTPUT", "FORWARD"):
        return False
    if _str(r, "action") != "ACCEPT" and _str(r, "target") != "ACCEPT":
        return False
    if not _has_source_port(r):
        return False
    if _has_dest_port(r):
        return False
    state = _str(r, "state")
    if state:
        states = [s.strip().upper() for s in state.split(",")]
        if "ESTABLISHED" in states or "RELATED" in states:
            return False
    return True


def _admin_range(r: object, admin_nets: list[IPv4Network | IPv6Network]) -> bool:
    src_range = _str(r, "src_range")
    if src_range and "-" in src_range:
        start_str, end_str = src_range.split("-", 1)
        try:
            start_ip = ipaddress.ip_address(start_str.strip())
            end_ip = ipaddress.ip_address(end_str.strip())
            return all(start_ip in net and end_ip in net for net in admin_nets)
        except ValueError:
            pass

    src = _str(r, "source")
    if not src:
        src_nets = _list(r, "sources")
        if src_nets:
            try:
                src_net = (
                    ipaddress.ip_network(src_nets[0], strict=False)
                    if isinstance(src_nets[0], str)
                    else src_nets[0]
                )
                if not isinstance(src_net, (IPv4Network, IPv6Network)):
                    return False
                return any(
                    (isinstance(src_net, IPv4Network) and isinstance(n, IPv4Network)
                     and src_net.subnet_of(n))
                    or (isinstance(src_net, IPv6Network) and isinstance(n, IPv6Network)
                        and src_net.subnet_of(n))
                    for n in admin_nets
                )
            except (ValueError, AttributeError, TypeError):
                pass
        return False

    try:
        src_net = ipaddress.ip_network(src, strict=False)
        return any(
            (isinstance(src_net, IPv4Network) and isinstance(n, IPv4Network)
             and src_net.subnet_of(n))
            or (isinstance(src_net, IPv6Network) and isinstance(n, IPv6Network)
                and src_net.subnet_of(n))
            for n in admin_nets
        )
    except (ValueError, TypeError):
        return False


# --------------------------------------------------------------------------- #
#  Result dataclass
# --------------------------------------------------------------------------- #

def _new_string_list() -> list[str]:
    return []


@dataclass
class AuditResult:
    default_policy: tuple[bool, str] = (False, "")
    missing_estab: list[str] = field(default_factory=_new_string_list)
    ssh_no_comment: list[str] = field(default_factory=_new_string_list)
    ssh_open_source: list[str] = field(default_factory=_new_string_list)
    input_no_port: list[str] = field(default_factory=_new_string_list)
    output_no_port: list[str] = field(default_factory=_new_string_list)
    input_fully_open: list[str] = field(default_factory=_new_string_list)
    output_fully_open: list[str] = field(default_factory=_new_string_list)
    ssh_outside_admin: list[str] = field(default_factory=_new_string_list)
    sport_spoofable: list[str] = field(default_factory=_new_string_list)

    def has_failures(self) -> bool:
        return (
            not self.default_policy[0]
            or bool(self.ssh_no_comment)
            or bool(self.ssh_open_source)
            or bool(self.input_no_port)
            or bool(self.output_no_port)
            or bool(self.input_fully_open)
            or bool(self.output_fully_open)
            or bool(self.ssh_outside_admin)
            or bool(self.sport_spoofable)
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "default_policy": {"passed": self.default_policy[0], "reason": self.default_policy[1]},
            "missing_established_related": self.missing_estab,
            "ssh_missing_comment": self.ssh_no_comment,
            "ssh_open_source": self.ssh_open_source,
            "input_no_port": self.input_no_port,
            "output_no_port": self.output_no_port,
            "input_fully_open": self.input_fully_open,
            "output_fully_open": self.output_fully_open,
            "ssh_outside_admin": self.ssh_outside_admin,
            "sport_spoofable": self.sport_spoofable,
        }


# --------------------------------------------------------------------------- #
#  Main audit runner
# --------------------------------------------------------------------------- #

def run_audit(chains: Mapping[str, Chain], admin_cidrs: list[str] | None = None) -> AuditResult:
    """
    Run the 10-point security audit on parsed chains.

    Args:
        chains: dict[str, Chain] from any parser
        admin_cidrs: list of trusted admin CIDR strings (e.g. ["10.0.0.0/8"])

    Returns:
        AuditResult
    """
    admin_nets: list[IPv4Network | IPv6Network] = []
    if admin_cidrs:
        for cidr in admin_cidrs:
            try:
                admin_nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass

    all_rules: list[Rule] = []
    rules_by_chain: dict[str, list[Rule]] = {}
    policies: dict[str, str] = {}

    for name, chain in chains.items():
        policies[name] = chain.default_policy or ""
        rules_by_chain[name] = chain.rules
        all_rules.extend(chain.rules)

    inbound_chain_names = [name for name in chains if name not in ("OUTPUT", "FORWARD")]
    if "INPUT" in chains:
        inbound_chain_names = ["INPUT"]
    inbound_rules = [rule for name in inbound_chain_names for rule in rules_by_chain.get(name, [])]

    # 1. Default policy
    explicit_drop = {ch: any(
        (_str(r, "action") == d or _str(r, "target") == d)
        for r in rules_by_chain.get(ch, [])
        for d in ("DROP", "REJECT")
    ) for ch in ("INPUT", "OUTPUT")}

    inp_pol = policies.get("INPUT", "").upper()
    out_pol = policies.get("OUTPUT", "").upper()
    if inp_pol in ("DROP", "REJECT") and out_pol in ("DROP", "REJECT"):
        policy_ok, policy_reason = True, "Default policy INPUT/OUTPUT = DROP/REJECT"
    elif "INPUT" not in chains and "OUTPUT" not in chains and inbound_chain_names:
        policy_ok, policy_reason = True, "firewalld zone targets control inbound traffic; no INPUT/OUTPUT chains are present"
    elif explicit_drop.get("INPUT") and explicit_drop.get("OUTPUT"):
        policy_ok, policy_reason = True, "Co rule '-j DROP'/'-j REJECT' tuong minh o INPUT va OUTPUT"
    else:
        policy_ok, policy_reason = False, (
            f"INPUT policy={inp_pol or 'NOT SET'}, "
            f"OUTPUT policy={out_pol or 'NOT SET'}, "
            f"INPUT co DROP/REJECT={explicit_drop.get('INPUT')}, "
            f"OUTPUT co DROP/REJECT={explicit_drop.get('OUTPUT')}"
        )

    # 1c. Missing ESTABLISHED,RELATED
    missing_estab: list[str] = []
    for ch in ("INPUT", "OUTPUT"):
        ch_pol = policies.get(ch)
        ch_rules = rules_by_chain.get(ch, [])
        if not ch_rules and not ch_pol:
            continue
        if ch_pol == "ACCEPT" and not explicit_drop.get(ch):
            continue
        has_estab = any(
            (_str(r, "action") == "ACCEPT" or _str(r, "target") == "ACCEPT")
            and bool(_str(r, "state"))
            and (
                (state := _str(r, "state")) is not None
                and ("ESTABLISHED" in state.upper() or "RELATED" in state.upper())
            )
            for r in ch_rules
        )
        if not has_estab:
            missing_estab.append(ch)

    # 2a. SSH missing comment
    ssh_no_comment: list[str] = []
    for r in all_rules:
        if _is_ssh_relevant(r):
            if not _str(r, "has_comment"):
                if not admin_nets or not _admin_range(r, admin_nets):
                    ssh_no_comment.append(_str(r, "raw_line") or "")

    # 2b. SSH open source
    ssh_open_source: list[str] = []
    for r in all_rules:
        if _is_ssh_relevant(r):
            has_src = bool(_str(r, "source")) or bool(_str(r, "src_range")) or not _is_unrestricted_source(r)
            if not has_src:
                ssh_open_source.append(_str(r, "raw_line") or "")

    # 3a. INPUT without dest port restriction
    input_no_port: list[str] = []
    for r in inbound_rules:
        if _str(r, "action") != "ACCEPT" and _str(r, "target") != "ACCEPT":
            continue
        if _is_loopback(r):
            continue
        if _is_estab_related_only(r):
            continue
        if _proto_has_no_ports(r):
            continue
        if not _is_state_new(r):
            continue
        if not _has_dest_port(r):
            if _is_spoofable_sport_only(r):
                continue
            input_no_port.append(_str(r, "raw_line") or "")

    # 3b. OUTPUT without dest port restriction
    output_no_port: list[str] = []
    for r in rules_by_chain.get("OUTPUT", []):
        if _str(r, "action") != "ACCEPT" and _str(r, "target") != "ACCEPT":
            continue
        if _is_loopback(r):
            continue
        if _is_estab_related_only(r):
            continue
        if _proto_has_no_ports(r):
            continue
        if not _is_state_new(r):
            continue
        if not _has_dest_port(r):
            output_no_port.append(_str(r, "raw_line") or "")

    # 4a. INPUT fully open
    input_fully_open: list[str] = []
    for r in inbound_rules:
        if _is_fully_open_accept(r, "INPUT"):
            input_fully_open.append(_str(r, "raw_line") or "")

    # 4b. OUTPUT fully open
    output_fully_open: list[str] = []
    for r in rules_by_chain.get("OUTPUT", []):
        if _is_fully_open_accept(r, "OUTPUT"):
            output_fully_open.append(_str(r, "raw_line") or "")

    # 5. SSH outside admin range
    ssh_outside_admin: list[str] = []
    if admin_nets:
        for r in all_rules:
            if _is_ssh_relevant(r) and not _admin_range(r, admin_nets):
                ssh_outside_admin.append(_str(r, "raw_line") or "")

    # 6. Sport-only spoofable
    sport_spoofable: list[str] = []
    for r in inbound_rules:
        if _is_spoofable_sport_only(r):
            sport_spoofable.append(_str(r, "raw_line") or "")

    return AuditResult(
        default_policy=(policy_ok, policy_reason),
        missing_estab=missing_estab,
        ssh_no_comment=[r for r in ssh_no_comment if r],
        ssh_open_source=[r for r in ssh_open_source if r],
        input_no_port=[r for r in input_no_port if r],
        output_no_port=[r for r in output_no_port if r],
        input_fully_open=[r for r in input_fully_open if r],
        output_fully_open=[r for r in output_fully_open if r],
        ssh_outside_admin=[r for r in ssh_outside_admin if r],
        sport_spoofable=[r for r in sport_spoofable if r],
    )
