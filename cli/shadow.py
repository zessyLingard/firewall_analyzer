#!/usr/bin/env python3
"""
cli/shadow.py — Shadowing analysis CLI.

Usage:
    python -m cli.shadow iptables.txt
    python -m cli.shadow rules.nft --output shadow.txt
"""

import argparse
import sys

sys.stdout.reconfigure(encoding="utf-8")

from firewall_analyzer.shadowing import analyze_shadowing, format_shadowing_text, format_shadowing_json
from firewall_analyzer.parsers import load_rules


def main():
    parser = argparse.ArgumentParser(description="Analyze rule shadowing in firewall rulesets")
    parser.add_argument("file", help="Firewall ruleset file")
    parser.add_argument(
        "--format",
        choices=["auto", "iptables", "nftables", "firewalld", "ufw"],
        default="auto",
    )
    parser.add_argument("--output-format", choices=["text", "json"], default="text")
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

    findings = analyze_shadowing(chains)
    output = format_shadowing_json(findings) if args.output_format == "json" else format_shadowing_text(findings)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
    else:
        print(output)

    full_shadows = sum(1 for f in findings if f.shadow_type == "FULL")
    unreachable = sum(1 for f in findings if f.shadow_type == "UNREACHABLE")
    sys.exit(1 if full_shadows > 0 or unreachable > 0 else 0)


if __name__ == "__main__":
    main()
