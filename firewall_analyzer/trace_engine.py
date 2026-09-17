#!/usr/bin/env python3
"""
trace_engine.py — Packet tracing simulation for firewall rulesets.

Simulates packet traversal through chains, returning detailed match information
for each rule evaluated. Supports iptables, nftables, and firewalld parsers
via the unified Chain/Rule model from core_models.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from ipaddress import IPv4Network, IPv6Network, IPv4Address, IPv6Address

from firewall_analyzer.models import Chain, Rule, PortRange


@dataclass
class Packet:
    """Packet to trace through firewall rules."""
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "tcp"
    in_iface: Optional[str] = None
    out_iface: Optional[str] = None
    state: Optional[str] = None

    def __post_init__(self):
        self.protocol = self.protocol.lower()
        if self.state:
            self.state = self.state.upper()


@dataclass
class TraceResult:
    """Result of evaluating one rule against a packet."""
    chain: str
    rule_index: int
    rule: Rule
    matched: bool
    match_reasons: list[str] = field(default_factory=list)
    mismatch_reasons: list[str] = field(default_factory=list)
    action: str = ""
    terminated: bool = False
    verdict: str = "CONTINUE"  # ACCEPT, DROP, REJECT, LOG, NOTRACK, CONTINUE, RETURN, GOTO, JUMP


@dataclass
class TraceContext:
    """Execution context for packet tracing."""
    chains: dict[str, Chain]
    current_chain: str
    packet: Packet
    call_stack: list[str] = field(default_factory=list)  # for jump/return tracking
    visited_rules: set = field(default_factory=set)  # (chain, rule_index) to prevent loops
    max_depth: int = 100  # prevent infinite recursion


def trace_packet(chains: dict[str, Chain], packet: Packet, start_chain: str = "INPUT") -> list[TraceResult]:
    """
    Trace a packet through the firewall ruleset.
    
    Args:
        chains: Dictionary of chain name -> Chain object
        packet: Packet to trace
        start_chain: Starting chain (default: INPUT)
    
    Returns:
        List of TraceResult for each rule evaluated in order
    """
    ctx = TraceContext(chains=chains, current_chain=start_chain, packet=packet)
    results: list[TraceResult] = []
    
    _trace_chain(ctx, results)
    return results


def _trace_chain(ctx: TraceContext, results: list[TraceResult]) -> str:
    """
    Trace packet through a single chain.
    Returns the final verdict: ACCEPT, DROP, REJECT, RETURN, or CONTINUE (fall through to policy).
    """
    chain = ctx.chains.get(ctx.current_chain)
    if not chain:
        return "CONTINUE"
    
    for idx, rule in enumerate(chain.rules):
        rule_key = (ctx.current_chain, idx)
        if rule_key in ctx.visited_rules:
            results.append(TraceResult(
                chain=ctx.current_chain,
                rule_index=idx,
                rule=rule,
                matched=False,
                mismatch_reasons=["Loop detected (rule already visited)"],
                action="LOOP",
                terminated=True,
                verdict="LOOP"
            ))
            return "LOOP"
        
        ctx.visited_rules.add(rule_key)
        
        result = _evaluate_rule(ctx, rule, idx, results)
        results.append(result)
        
        if result.terminated:
            return result.verdict
        
        # If rule matched but didn't terminate (e.g., LOG), continue to next rule
        if result.matched and result.verdict == "CONTINUE":
            continue
        
        # If rule didn't match, continue to next rule
        if not result.matched:
            continue
    
    # Fell through all rules - return default policy
    if chain.default_policy:
        return chain.default_policy.upper()
    return "CONTINUE"


def _evaluate_rule(ctx: TraceContext, rule: Rule, rule_index: int, results: list) -> TraceResult:
    """Evaluate a single rule against the packet."""
    packet = ctx.packet
    match_reasons = []
    mismatch_reasons = []
    
    # Check protocol
    if rule.protocol:
        rule_proto = rule.protocol.lower()
        if rule_proto not in ("all", "any", packet.protocol):
            if rule_proto in ("tcp", "6") and packet.protocol == "tcp":
                pass
            elif rule_proto in ("udp", "17") and packet.protocol == "udp":
                pass
            elif rule_proto in ("icmp", "1", "icmpv6", "ipv6-icmp", "58") and packet.protocol in ("icmp", "icmpv6"):
                pass
            else:
                mismatch_reasons.append(f"protocol: packet={packet.protocol}, rule={rule_proto}")
                return TraceResult(
                    chain=ctx.current_chain,
                    rule_index=rule_index,
                    rule=rule,
                    matched=False,
                    mismatch_reasons=mismatch_reasons,
                    action=rule.action,
                    terminated=False,
                    verdict="CONTINUE"
                )
        match_reasons.append(f"protocol: {packet.protocol} matches {rule.protocol}")
    
    # Check source IP
    if rule.sources:
        src_matched = False
        for src_net in rule.sources:
            try:
                if isinstance(src_net, (IPv4Network, IPv6Network)):
                    packet_ip = IPv4Address(packet.src_ip) if ":" not in packet.src_ip else IPv6Address(packet.src_ip)
                    if packet_ip in src_net:
                        src_matched = True
                        match_reasons.append(f"src: {packet.src_ip} in {src_net}")
                        break
            except ValueError:
                pass
        if not src_matched:
            mismatch_reasons.append(f"src: {packet.src_ip} not in any rule source")
            return TraceResult(
                chain=ctx.current_chain,
                rule_index=rule_index,
                rule=rule,
                matched=False,
                mismatch_reasons=mismatch_reasons,
                action=rule.action,
                terminated=False,
                verdict="CONTINUE"
            )
    else:
        match_reasons.append("src: any (no restriction)")
    
    # Check destination IP
    if rule.destinations:
        dst_matched = False
        for dst_net in rule.destinations:
            try:
                if isinstance(dst_net, (IPv4Network, IPv6Network)):
                    packet_ip = IPv4Address(packet.dst_ip) if ":" not in packet.dst_ip else IPv6Address(packet.dst_ip)
                    if packet_ip in dst_net:
                        dst_matched = True
                        match_reasons.append(f"dst: {packet.dst_ip} in {dst_net}")
                        break
            except ValueError:
                pass
        if not dst_matched:
            mismatch_reasons.append(f"dst: {packet.dst_ip} not in any rule destination")
            return TraceResult(
                chain=ctx.current_chain,
                rule_index=rule_index,
                rule=rule,
                matched=False,
                mismatch_reasons=mismatch_reasons,
                action=rule.action,
                terminated=False,
                verdict="CONTINUE"
            )
    else:
        match_reasons.append("dst: any (no restriction)")
    
    # Check source port (for TCP/UDP)
    if packet.protocol in ("tcp", "udp") and rule.source_ports:
        sport_matched = False
        for pr in rule.source_ports:
            if pr.contains(packet.src_port):
                sport_matched = True
                match_reasons.append(f"sport: {packet.src_port} in {pr}")
                break
        if not sport_matched:
            mismatch_reasons.append(f"sport: {packet.src_port} not in rule source ports")
            return TraceResult(
                chain=ctx.current_chain,
                rule_index=rule_index,
                rule=rule,
                matched=False,
                mismatch_reasons=mismatch_reasons,
                action=rule.action,
                terminated=False,
                verdict="CONTINUE"
            )
    elif packet.protocol in ("tcp", "udp") and packet.src_port > 0:
        match_reasons.append(f"sport: {packet.src_port} (no restriction)")
    
    # Check destination port (for TCP/UDP)
    if packet.protocol in ("tcp", "udp") and rule.ports:
        dport_matched = False
        for pr in rule.ports:
            if pr.contains(packet.dst_port):
                dport_matched = True
                match_reasons.append(f"dport: {packet.dst_port} in {pr}")
                break
        if not dport_matched:
            mismatch_reasons.append(f"dport: {packet.dst_port} not in rule destination ports")
            return TraceResult(
                chain=ctx.current_chain,
                rule_index=rule_index,
                rule=rule,
                matched=False,
                mismatch_reasons=mismatch_reasons,
                action=rule.action,
                terminated=False,
                verdict="CONTINUE"
            )
    elif packet.protocol in ("tcp", "udp") and packet.dst_port > 0:
        match_reasons.append(f"dport: {packet.dst_port} (no restriction)")
    
    # Check interface (in_interface)
    if rule.in_interface and rule.in_interface != packet.in_iface:
        # Handle negation (!)
        if not rule.is_negated:
            mismatch_reasons.append(f"in_iface: packet={packet.in_iface}, rule={rule.in_interface}")
            return TraceResult(
                chain=ctx.current_chain,
                rule_index=rule_index,
                rule=rule,
                matched=False,
                mismatch_reasons=mismatch_reasons,
                action=rule.action,
                terminated=False,
                verdict="CONTINUE"
            )
    elif rule.in_interface:
        match_reasons.append(f"in_iface: {packet.in_iface} matches {rule.in_interface}")
    
    # Check interface (out_interface)
    if rule.out_interface and rule.out_interface != packet.out_iface:
        if not rule.is_negated:
            mismatch_reasons.append(f"out_iface: packet={packet.out_iface}, rule={rule.out_interface}")
            return TraceResult(
                chain=ctx.current_chain,
                rule_index=rule_index,
                rule=rule,
                matched=False,
                mismatch_reasons=mismatch_reasons,
                action=rule.action,
                terminated=False,
                verdict="CONTINUE"
            )
    elif rule.out_interface:
        match_reasons.append(f"out_iface: {packet.out_iface} matches {rule.out_interface}")
    
    # Check connection state
    if rule.states:
        state_matched = False
        # Handle comma-separated states like "RELATED,ESTABLISHED"
        rule_states = []
        for rs in rule.states:
            rule_states.extend([s.strip().upper() for s in rs.split(",")])
        
        for rule_state in rule_states:
            if rule_state == packet.state:
                state_matched = True
                match_reasons.append(f"state: {packet.state} matches {rule_state}")
                break
        if not state_matched:
            mismatch_reasons.append(f"state: {packet.state} not in rule states {rule_states}")
            return TraceResult(
                chain=ctx.current_chain,
                rule_index=rule_index,
                rule=rule,
                matched=False,
                mismatch_reasons=mismatch_reasons,
                action=rule.action,
                terminated=False,
                verdict="CONTINUE"
            )
    elif packet.state:
        match_reasons.append(f"state: {packet.state} (no restriction)")
    
    # All checks passed - rule matches
    action = rule.action.upper()
    
    # Determine verdict based on action
    action_upper = action.upper()
    
    # Handle jump to another chain (action is the target chain name)
    if action_upper not in ("ACCEPT", "DROP", "REJECT", "LOG", "NOTRACK", "RETURN"):
        # This is a jump/goto to another chain
        target_chain = action_upper
        if target_chain in ctx.chains:
            # Trace into the target chain
            ctx.call_stack.append(ctx.current_chain)
            old_chain = ctx.current_chain
            ctx.current_chain = target_chain
            verdict = _trace_chain(ctx, results)
            ctx.current_chain = old_chain
            ctx.call_stack.pop()
            
            if verdict == "RETURN":
                # RETURN from jumped chain - continue in current chain
                return TraceResult(
                    chain=ctx.current_chain,
                    rule_index=rule_index,
                    rule=rule,
                    matched=True,
                    match_reasons=match_reasons + [f"JUMP to {target_chain} → returned {verdict}"],
                    action=f"JUMP:{target_chain}",
                    terminated=False,
                    verdict="CONTINUE"
                )
            elif verdict in ("ACCEPT", "DROP", "REJECT"):
                # Target chain terminated with terminating action
                return TraceResult(
                    chain=ctx.current_chain,
                    rule_index=rule_index,
                    rule=rule,
                    matched=True,
                    match_reasons=match_reasons + [f"JUMP to {target_chain} → {verdict}"],
                    action=f"JUMP:{target_chain}",
                    terminated=True,
                    verdict=verdict
                )
            else:
                # Target chain fell through (CONTINUE) - continue in current chain
                return TraceResult(
                    chain=ctx.current_chain,
                    rule_index=rule_index,
                    rule=rule,
                    matched=True,
                    match_reasons=match_reasons + [f"JUMP to {target_chain} → fell through (CONTINUE)"],
                    action=f"JUMP:{target_chain}",
                    terminated=False,
                    verdict="CONTINUE"
                )
        else:
            # Target chain doesn't exist - treat as continue with warning
            return TraceResult(
                chain=ctx.current_chain,
                rule_index=rule_index,
                rule=rule,
                matched=True,
                match_reasons=match_reasons + [f"JUMP to unknown chain {target_chain} (continues)"],
                action=f"JUMP:{target_chain}",
                terminated=False,
                verdict="CONTINUE"
            )
    
    if action_upper in ("ACCEPT", "DROP", "REJECT"):
        return TraceResult(
            chain=ctx.current_chain,
            rule_index=rule_index,
            rule=rule,
            matched=True,
            match_reasons=match_reasons,
            action=action,
            terminated=True,
            verdict=action
        )
    elif action == "LOG":
        return TraceResult(
            chain=ctx.current_chain,
            rule_index=rule_index,
            rule=rule,
            matched=True,
            match_reasons=match_reasons + ["LOG action (continues)"],
            action="LOG",
            terminated=False,
            verdict="CONTINUE"
        )
    elif action == "NOTRACK":
        return TraceResult(
            chain=ctx.current_chain,
            rule_index=rule_index,
            rule=rule,
            matched=True,
            match_reasons=match_reasons + ["NOTRACK action (continues)"],
            action="NOTRACK",
            terminated=False,
            verdict="CONTINUE"
        )
    elif action == "RETURN":
        return TraceResult(
            chain=ctx.current_chain,
            rule_index=rule_index,
            rule=rule,
            matched=True,
            match_reasons=match_reasons + ["RETURN to calling chain"],
            action="RETURN",
            terminated=True,
            verdict="RETURN"
        )
    elif action.startswith("JUMP:") or action.startswith("GOTO:"):
        target_chain = action.split(":", 1)[1]
        return TraceResult(
            chain=ctx.current_chain,
            rule_index=rule_index,
            rule=rule,
            matched=True,
            match_reasons=match_reasons + [f"{action} to chain {target_chain}"],
            action=action,
            terminated=False,
            verdict=f"{action.split(':')[0]}:{target_chain}"
        )
    
    # Unknown action - treat as continue
    return TraceResult(
        chain=ctx.current_chain,
        rule_index=rule_index,
        rule=rule,
        matched=True,
        match_reasons=match_reasons + [f"unknown action {action} (continues)"],
        action=action,
        terminated=False,
        verdict="CONTINUE"
    )


def format_trace_text(results: list[TraceResult], packet: Packet) -> str:
    """Format trace results as human-readable text."""
    lines = []
    lines.append("=" * 70)
    lines.append(f"PACKET TRACE: {packet.src_ip}:{packet.src_port} -> {packet.dst_ip}:{packet.dst_port} ({packet.protocol.upper()})")
    if packet.in_iface:
        lines.append(f"  in_iface={packet.in_iface}")
    if packet.out_iface:
        lines.append(f"  out_iface={packet.out_iface}")
    if packet.state:
        lines.append(f"  state={packet.state}")
    lines.append("=" * 70)
    
    current_chain = None
    for r in results:
        if r.chain != current_chain:
            current_chain = r.chain
            lines.append(f"\n>>> Chain: {current_chain}")
        
        if r.matched:
            status = "✓ MATCH"
            verdict_str = f" → {r.verdict}" if r.verdict != "CONTINUE" else ""
        else:
            status = "✗ NO MATCH"
            verdict_str = ""
        
        lines.append(f"  [{r.rule_index:3d}] {status}{verdict_str}")
        
        if r.matched:
            for reason in r.match_reasons:
                lines.append(f"         ✓ {reason}")
        else:
            for reason in r.mismatch_reasons:
                lines.append(f"         ✗ {reason}")
        
        if r.rule and r.rule.raw_line:
            lines.append(f"         raw: {r.rule.raw_line[:100]}")
    
    lines.append("\n" + "=" * 70)
    final_verdict = results[-1].verdict if results else "CONTINUE"
    lines.append(f"FINAL VERDICT: {final_verdict}")
    return "\n".join(lines)


def format_trace_json(results: list[TraceResult], packet: Packet) -> str:
    """Format trace results as JSON."""
    import json
    from dataclasses import asdict
    
    data = {
        "packet": {
            "src_ip": packet.src_ip,
            "dst_ip": packet.dst_ip,
            "src_port": packet.src_port,
            "dst_port": packet.dst_port,
            "protocol": packet.protocol,
            "in_iface": packet.in_iface,
            "out_iface": packet.out_iface,
            "state": packet.state,
        },
        "trace": []
    }
    
    for r in results:
        rule_data = {
            "chain": r.chain,
            "rule_index": r.rule_index,
            "matched": r.matched,
            "match_reasons": r.match_reasons,
            "mismatch_reasons": r.mismatch_reasons,
            "action": r.action,
            "terminated": r.terminated,
            "verdict": r.verdict,
            "raw_line": r.rule.raw_line if r.rule else "",
        }
        data["trace"].append(rule_data)
    
    data["final_verdict"] = results[-1].verdict if results else "CONTINUE"
    return json.dumps(data, indent=2)