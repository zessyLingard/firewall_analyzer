#!/usr/bin/env python3
"""
shadowing.py — Rule shadowing and reachability analysis for firewall rulesets.

Detects:
- FULL shadowing: Rule A completely shadows Rule B (all packets matching B also match A, and A terminates)
- PARTIAL shadowing: Rule A partially overlaps with Rule B
- REDUNDANT rules: Multiple rules with identical match criteria
- UNREACHABLE rules: Rules that can never match due to preceding terminating rules
"""

from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Mapping
from typing import Optional
from ipaddress import IPv4Network, IPv6Network, ip_network, ip_address

from firewall_analyzer.models import Chain, Rule, PortRange


@dataclass
class ShadowFinding:
    """Represents a shadowing or redundancy finding."""
    shadowing_rule: Rule
    shadowed_rule: Rule
    shadow_type: str  # "FULL" | "PARTIAL" | "REDUNDANT" | "UNREACHABLE"
    chain: str
    overlap_details: dict
    shadowing_rule_index: int
    shadowed_rule_index: int
    description: str


def networks_overlap(net1, net2) -> bool:
    """Check if two IP networks overlap."""
    try:
        # Convert to ip_network if needed
        if isinstance(net1, str):
            net1 = ip_network(net1, strict=False)
        if isinstance(net2, str):
            net2 = ip_network(net2, strict=False)
        
        # Check if they're the same version
        if net1.version != net2.version:
            return False
        
        # Check overlap
        return net1.overlaps(net2)
    except (ValueError, AttributeError):
        return False


def network_contains(net1, net2) -> bool:
    """Check if net1 contains net2 (net2 is subset of net1)."""
    try:
        if isinstance(net1, str):
            net1 = ip_network(net1, strict=False)
        if isinstance(net2, str):
            net2 = ip_network(net2, strict=False)
        
        if net1.version != net2.version:
            return False
        
        return net2.subnet_of(net1)
    except (ValueError, AttributeError):
        return False


def port_ranges_overlap(ports1: list[PortRange], ports2: list[PortRange]) -> bool:
    """Check if two lists of port ranges overlap."""
    if not ports1 or not ports2:
        return True  # No restriction = matches all ports
    
    for p1 in ports1:
        for p2 in ports2:
            if p1.min_port <= p2.max_port and p2.min_port <= p1.max_port:
                return True
    return False


def port_range_contains(ports1: list[PortRange], ports2: list[PortRange]) -> bool:
    """Check if ports1 contains ports2 (every port in ports2 is also in ports1)."""
    if not ports2:
        return True  # Empty restriction is contained by anything
    if not ports1:
        return False  # Non-empty not contained by empty
    
    for p2 in ports2:
        contained = False
        for p1 in ports1:
            if p1.min_port <= p2.min_port and p1.max_port >= p2.max_port:
                contained = True
                break
        if not contained:
            return False
    return True


def addresses_overlap(addrs1: list, addrs2: list) -> bool:
    """Check if two lists of IP networks overlap."""
    if not addrs1 or not addrs2:
        return True  # No restriction = matches all
    
    for a1 in addrs1:
        for a2 in addrs2:
            if networks_overlap(a1, a2):
                return True
    return False


def addresses_contain(addrs1: list, addrs2: list) -> bool:
    """Check if addrs1 contains addrs2 (every addr in addrs2 is also in addrs1)."""
    if not addrs2:
        return True
    if not addrs1:
        return False
    
    for a2 in addrs2:
        contained = False
        for a1 in addrs1:
            if network_contains(a1, a2):
                contained = True
                break
        if not contained:
            return False
    return True


def protocols_match(proto1: Optional[str], proto2: Optional[str]) -> bool:
    """Check if two protocols are compatible (could match same traffic)."""
    if not proto1 or not proto2:
        return True  # No restriction = matches all
    
    p1 = proto1.lower()
    p2 = proto2.lower()
    
    if p1 == p2:
        return True
    if p1 in ("all", "any") or p2 in ("all", "any"):
        return True
    
    # Numeric protocol numbers
    proto_map = {"tcp": "6", "udp": "17", "icmp": "1", "icmpv6": "58"}
    if proto_map.get(p1) == p2 or proto_map.get(p2) == p1:
        return True
    
    return False


def interfaces_match(iface1: Optional[str], iface2: Optional[str]) -> bool:
    """Check if two interfaces could match same traffic."""
    if not iface1 or not iface2:
        return True
    return iface1 == iface2


def states_overlap(states1: list[str], states2: list[str]) -> bool:
    """Check if two state lists overlap."""
    if not states1 or not states2:
        return True
    
    s1 = set(s.upper() for state in states1 for s in state.split(","))
    s2 = set(s.upper() for state in states2 for s in state.split(","))
    
    return bool(s1 & s2)


def rules_overlap(rule1: Rule, rule2: Rule) -> tuple[bool, dict]:
    """
    Check if two rules could match the same packet.
    Returns (overlaps, overlap_details).
    """
    details = {}
    
    # Protocol
    proto_match = protocols_match(rule1.protocol, rule2.protocol)
    details["protocol"] = proto_match
    if not proto_match:
        return False, details
    
    # Source IP
    src_overlap = addresses_overlap(rule1.sources, rule2.sources)
    details["src_overlap"] = src_overlap
    if not src_overlap:
        return False, details
    
    # Destination IP
    dst_overlap = addresses_overlap(rule1.destinations, rule2.destinations)
    details["dst_overlap"] = dst_overlap
    if not dst_overlap:
        return False, details
    
    # Source port
    sport_overlap = port_ranges_overlap(rule1.source_ports, rule2.source_ports)
    details["sport_overlap"] = sport_overlap
    if not sport_overlap:
        return False, details
    
    # Destination port
    dport_overlap = port_ranges_overlap(rule1.ports, rule2.ports)
    details["dport_overlap"] = dport_overlap
    if not dport_overlap:
        return False, details
    
    # Input interface
    in_iface_match = interfaces_match(rule1.in_interface, rule2.in_interface)
    details["in_iface_match"] = in_iface_match
    if not in_iface_match:
        return False, details
    
    # Output interface
    out_iface_match = interfaces_match(rule1.out_interface, rule2.out_interface)
    details["out_iface_match"] = out_iface_match
    if not out_iface_match:
        return False, details
    
    # State
    state_overlap = states_overlap(rule1.states, rule2.states)
    details["state_overlap"] = state_overlap
    if not state_overlap:
        return False, details
    
    return True, details


def rule1_contains_rule2(rule1: Rule, rule2: Rule) -> tuple[bool, dict]:
    """
    Check if rule1's match criteria completely contains rule2's (rule1 is broader or equal).
    Returns (contains, details).
    """
    details = {}
    
    # Protocol: rule1 must be broader or equal
    proto_contain = not rule2.protocol or (rule1.protocol and protocols_match(rule1.protocol, rule2.protocol))
    if rule1.protocol and rule1.protocol.lower() in ("all", "any"):
        proto_contain = True
    elif rule2.protocol and rule2.protocol.lower() in ("all", "any"):
        proto_contain = False
    elif not rule1.protocol and rule2.protocol:
        proto_contain = True  # No restriction contains specific
    details["protocol"] = proto_contain
    if not proto_contain:
        return False, details
    
    # Source IP: rule1 must contain rule2
    src_contain = addresses_contain(rule1.sources, rule2.sources)
    details["src_contain"] = src_contain
    if not src_contain:
        return False, details
    
    # Destination IP: rule1 must contain rule2
    dst_contain = addresses_contain(rule1.destinations, rule2.destinations)
    details["dst_contain"] = dst_contain
    if not dst_contain:
        return False, details
    
    # Source port: rule1 must contain rule2
    sport_contain = port_range_contains(rule1.source_ports, rule2.source_ports)
    details["sport_contain"] = sport_contain
    if not sport_contain:
        return False, details
    
    # Destination port: rule1 must contain rule2
    dport_contain = port_range_contains(rule1.ports, rule2.ports)
    details["dport_contain"] = dport_contain
    if not dport_contain:
        return False, details
    
    # Interface: rule1 must be less restrictive (None contains specific)
    in_iface_contain = not rule1.in_interface or (rule1.in_interface == rule2.in_interface)
    details["in_iface"] = in_iface_contain
    if not in_iface_contain:
        return False, details
    
    out_iface_contain = not rule1.out_interface or (rule1.out_interface == rule2.out_interface)
    details["out_iface"] = out_iface_contain
    if not out_iface_contain:
        return False, details
    
    # State: rule1 must be less restrictive or equal
    state_contain = not rule2.states or (rule1.states and states_overlap(rule1.states, rule2.states))
    if not rule1.states and rule2.states:
        state_contain = True  # No restriction contains specific
    elif rule1.states and not rule2.states:
        state_contain = False
    details["state"] = state_contain
    if not state_contain:
        return False, details
    
    return True, details


def is_terminating_action(action: str) -> bool:
    """Check if an action terminates packet processing in the chain."""
    return action.upper() in ("ACCEPT", "DROP", "REJECT")


def analyze_chain_shadowing(chain: Chain) -> list[ShadowFinding]:
    """Analyze shadowing within a single chain."""
    findings = []
    rules = chain.rules
    
    # Check for FULL shadowing: a MORE GENERAL terminating rule before a MORE SPECIFIC rule
    for i, rule_i in enumerate(rules):
        if not is_terminating_action(rule_i.action):
            continue
        
        # Check if this terminating rule shadows any subsequent rules
        for j in range(i + 1, len(rules)):
            rule_j = rules[j]
            
            # Skip if rule_j is also a terminating action (both terminate, order matters less)
            if is_terminating_action(rule_j.action):
                continue
            
            overlaps, overlap_details = rules_overlap(rule_i, rule_j)
            if not overlaps:
                continue
            
            # Check if rule_i is MORE GENERAL (contains) rule_j
            contains, contain_details = rule1_contains_rule2(rule_i, rule_j)
            
            if contains:
                # FULL shadowing - rule_i (general) completely contains rule_j (specific)
                # This is a problem: general rule comes before specific rule
                findings.append(ShadowFinding(
                    shadowing_rule=rule_i,
                    shadowed_rule=rule_j,
                    shadow_type="FULL",
                    chain=chain.name,
                    overlap_details=contain_details,
                    shadowing_rule_index=i,
                    shadowed_rule_index=j,
                    description=f"Rule {i} ({rule_i.action}) is general and shadows specific rule {j} ({rule_j.action})"
                ))
            else:
                # Check if rule_j is more general than rule_i (correct ordering)
                # This is fine - specific before general
                pass
    
    # Check for REDUNDANT rules (identical match criteria, different terminating actions)
    for i in range(len(rules)):
        for j in range(i + 1, len(rules)):
            if rules[i].action == rules[j].action:
                continue
            if not is_terminating_action(rules[i].action) or not is_terminating_action(rules[j].action):
                continue  # Only check redundancy for terminating rules
            
            contains_ij, _ = rule1_contains_rule2(rules[i], rules[j])
            contains_ji, _ = rule1_contains_rule2(rules[j], rules[i])
            
            if contains_ij and contains_ji:
                findings.append(ShadowFinding(
                    shadowing_rule=rules[i],
                    shadowed_rule=rules[j],
                    shadow_type="REDUNDANT",
                    chain=chain.name,
                    overlap_details={},
                    shadowing_rule_index=i,
                    shadowed_rule_index=j,
                    description=f"Rule {i} ({rules[i].action}) and rule {j} ({rules[j].action}) have identical match criteria"
                ))
    
    return findings


def analyze_unreachable_rules(chains: Mapping[str, Chain]) -> list[ShadowFinding]:
    """Find rules that can never be reached due to preceding terminating rules."""
    findings = []
    
    for chain_name, chain in chains.items():
        # Find first terminating rule that matches "any" packet (broad)
        broad_terminator_idx = None
        broad_terminator_rule = None
        
        for i, rule in enumerate(chain.rules):
            if not is_terminating_action(rule.action):
                continue
            
            # Check if rule has no restrictions (matches everything)
            is_broad = (
                not rule.protocol and
                not rule.sources and
                not rule.destinations and
                not rule.ports and
                not rule.source_ports and
                not rule.in_interface and
                not rule.out_interface and
                not rule.states
            )
            
            if is_broad:
                broad_terminator_idx = i
                broad_terminator_rule = rule
                break
        
        if broad_terminator_idx is not None:
            # All rules after this are unreachable
            for j in range(broad_terminator_idx + 1, len(chain.rules)):
                findings.append(ShadowFinding(
                    shadowing_rule=broad_terminator_rule,
                    shadowed_rule=chain.rules[j],
                    shadow_type="UNREACHABLE",
                    chain=chain_name,
                    overlap_details={},
                    shadowing_rule_index=broad_terminator_idx,
                    shadowed_rule_index=j,
                    description=f"Rule {j} unreachable due to broad terminating rule {broad_terminator_idx} ({broad_terminator_rule.action})"
                ))
    
    return findings


def analyze_shadowing(chains: Mapping[str, Chain]) -> list[ShadowFinding]:
    """
    Analyze shadowing across all chains.
    Returns list of ShadowFinding objects.
    """
    all_findings = []
    
    # Intra-chain shadowing
    for chain in chains.values():
        all_findings.extend(analyze_chain_shadowing(chain))
    
    # Unreachable rules
    all_findings.extend(analyze_unreachable_rules(chains))
    
    return all_findings


def format_shadowing_text(findings: list[ShadowFinding]) -> str:
    """Format shadowing findings as human-readable text."""
    if not findings:
        return "No shadowing or unreachable rules detected."
    
    lines = []
    lines.append("=" * 70)
    lines.append(f"SHADOWING ANALYSIS: {len(findings)} findings")
    lines.append("=" * 70)
    
    by_type = {}
    for f in findings:
        by_type.setdefault(f.shadow_type, []).append(f)
    
    for ftype in ["FULL", "PARTIAL", "REDUNDANT", "UNREACHABLE"]:
        if ftype not in by_type:
            continue
        
        lines.append(f"\n--- {ftype} SHADOWING ({len(by_type[ftype])}) ---")
        
        for f in by_type[ftype]:
            lines.append(f"\n  Chain: {f.chain}")
            lines.append(f"  Shadowing rule [{f.shadowing_rule_index}]: {f.shadowing_rule.action}")
            lines.append(f"    {f.shadowing_rule.raw_line[:100]}")
            lines.append(f"  Shadowed rule [{f.shadowed_rule_index}]: {f.shadowed_rule.action}")
            lines.append(f"    {f.shadowed_rule.raw_line[:100]}")
            
            if f.overlap_details:
                lines.append(f"  Overlap details:")
                for k, v in f.overlap_details.items():
                    lines.append(f"    {k}: {v}")
    
    return "\n".join(lines)


def format_shadowing_json(findings: list[ShadowFinding]) -> str:
    """Format shadowing findings as JSON."""
    import json
    
    data = {
        "total_findings": len(findings),
        "by_type": {},
        "findings": []
    }
    
    for f in findings:
        data["by_type"][f.shadow_type] = data["by_type"].get(f.shadow_type, 0) + 1
        
        finding_data = {
            "shadow_type": f.shadow_type,
            "chain": f.chain,
            "shadowing_rule_index": f.shadowing_rule_index,
            "shadowed_rule_index": f.shadowed_rule_index,
            "description": f.description,
            "shadowing_rule": {
                "action": f.shadowing_rule.action,
                "protocol": f.shadowing_rule.protocol,
                "raw_line": f.shadowing_rule.raw_line,
            },
            "shadowed_rule": {
                "action": f.shadowed_rule.action,
                "protocol": f.shadowed_rule.protocol,
                "raw_line": f.shadowed_rule.raw_line,
            },
            "overlap_details": f.overlap_details,
        }
        data["findings"].append(finding_data)
    
    return json.dumps(data, indent=2)