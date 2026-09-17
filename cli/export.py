#!/usr/bin/env python3
"""
cli/export.py — Export firewall audit results to HTML, SARIF, JSON.
"""

import argparse
import sys
import json

from firewall_analyzer.export import export_audit_json, export_sarif, export_html, write_export
from firewall_analyzer.parsers import load_rules

try:
    from firewall_analyzer.trace_engine import trace_packet, Packet
    from firewall_analyzer.shadowing import analyze_shadowing
    HAS_ANALYSIS = True
except ImportError:
    HAS_ANALYSIS = False


def main():
    parser = argparse.ArgumentParser(description="Export firewall audit results")
    parser.add_argument("file", help="Firewall ruleset file")
    parser.add_argument(
        "--format",
        choices=["auto", "iptables", "nftables", "firewalld", "ufw"],
        default="auto",
    )
    parser.add_argument(
        "--output-format",
        choices=["html", "sarif", "json"],
        default="html",
    )
    parser.add_argument("--output", required=True)
    parser.add_argument("--trace", action="store_true")
    parser.add_argument("--src")
    parser.add_argument("--dst")
    parser.add_argument("--sport", type=int, default=0)
    parser.add_argument("--dport", type=int)
    parser.add_argument("--proto", choices=["tcp", "udp", "icmp", "icmpv6"], default="tcp")
    parser.add_argument("--in-iface")
    parser.add_argument("--out-iface")
    parser.add_argument("--state", choices=["NEW", "ESTABLISHED", "RELATED", "INVALID"])
    parser.add_argument("--shadowing", action="store_true")
    parser.add_argument("--audit-results")
    args = parser.parse_args()

    try:
        chains = load_rules(args.file, format=args.format)
    except Exception as e:
        print(f"[ERROR] Parse failed: {e}", file=sys.stderr)
        sys.exit(2)

    if not chains:
        print(f"[ERROR] No chains in {args.file}", file=sys.stderr)
        sys.exit(2)

    trace_results = None
    packet = None
    if args.trace:
        if not args.src or not args.dst or args.dport is None:
            print("[ERROR] --trace requires --src, --dst, --dport", file=sys.stderr)
            sys.exit(2)
        packet = Packet(
            src_ip=args.src, dst_ip=args.dst,
            src_port=args.sport, dst_port=args.dport,
            protocol=args.proto,
            in_iface=args.in_iface,
            out_iface=args.out_iface,
            state=args.state,
        )
        trace_results = trace_packet(chains, packet, start_chain="INPUT")

    shadowing_findings = None
    if args.shadowing:
        shadowing_findings = analyze_shadowing(chains)

    audit_results = None
    if args.audit_results:
        with open(args.audit_results) as f:
            audit_results = json.load(f)

    if args.output_format == "html":
        output = export_html(
            chains=chains, audit_results=audit_results,
            trace_results=trace_results, shadowing_findings=shadowing_findings,
            packet=packet, filepath=args.file,
        )
    elif args.output_format == "sarif":
        output = export_sarif(
            chains=chains, audit_results=audit_results or {},
            trace_results=trace_results, shadowing_findings=shadowing_findings,
            filepath=args.file,
        )
    else:
        output = export_audit_json(
            chains=chains, trace_results=trace_results,
            shadowing_findings=shadowing_findings, packet=packet,
            filepath=args.file,
        )

    write_export(output, args.output)
    print(f"[INFO] Written to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
