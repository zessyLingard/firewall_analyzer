#!/usr/bin/env python3
"""
cli/trace.py — Packet tracing CLI.

Usage:
    python -m cli.trace iptables.txt --src 10.0.0.5 --dst 192.168.1.10 --dport 22 --proto tcp
    python -m cli.trace rules.nft --src 192.168.1.100 --dst 10.0.0.1 --dport 443 --proto tcp --format json
"""

import argparse
import sys

sys.stdout.reconfigure(encoding="utf-8")

from firewall_analyzer.trace_engine import trace_packet, Packet, format_trace_text, format_trace_json
from firewall_analyzer.parsers import load_rules


def main():
    parser = argparse.ArgumentParser(
        description="Trace a packet through firewall rules",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("file", help="Firewall ruleset file")
    parser.add_argument(
        "--format",
        choices=["auto", "iptables", "nftables", "firewalld", "ufw"],
        default="auto",
        help="Format (default: auto-detect)",
    )
    parser.add_argument("--chain", default="INPUT", help="Starting chain (default: INPUT)")
    parser.add_argument("--src", required=True, help="Source IP")
    parser.add_argument("--dst", required=True, help="Destination IP")
    parser.add_argument("--sport", type=int, default=0, help="Source port")
    parser.add_argument("--dport", type=int, required=True, help="Destination port")
    parser.add_argument(
        "--proto",
        choices=["tcp", "udp", "icmp", "icmpv6"],
        default="tcp",
        help="Protocol",
    )
    parser.add_argument("--in-iface", help="Input interface")
    parser.add_argument("--out-iface", help="Output interface")
    parser.add_argument("--state", choices=["NEW", "ESTABLISHED", "RELATED", "INVALID"])
    parser.add_argument(
        "--output-format",
        choices=["text", "json"],
        default="text",
    )
    parser.add_argument("--output", help="Output file")
    args = parser.parse_args()

    try:
        chains = load_rules(args.file, format=args.format)
    except Exception as e:
        print(f"[ERROR] Parse failed: {e}", file=sys.stderr)
        sys.exit(2)

    if not chains:
        print(f"[ERROR] No chains in {args.file}", file=sys.stderr)
        sys.exit(2)

    packet = Packet(
        src_ip=args.src,
        dst_ip=args.dst,
        src_port=args.sport,
        dst_port=args.dport,
        protocol=args.proto,
        in_iface=args.in_iface,
        out_iface=args.out_iface,
        state=args.state,
    )

    try:
        results = trace_packet(chains, packet, start_chain=args.chain)
    except Exception as e:
        print(f"[ERROR] Trace failed: {e}", file=sys.stderr)
        sys.exit(1)

    output = format_trace_json(results, packet) if args.output_format == "json" else format_trace_text(results, packet)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
    else:
        print(output)


if __name__ == "__main__":
    main()
