#!/usr/bin/env python3
"""
cli/export.py — Export firewall audit results to HTML, SARIF, JSON.
"""

import argparse
import sys
import json

from firewall_analyzer.export import export_audit_json, export_sarif, export_html, write_export
from firewall_analyzer.parsers import load_rules
from firewall_analyzer.shadowing import analyze_shadowing


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
            shadowing_findings=shadowing_findings, filepath=args.file,
        )
    elif args.output_format == "sarif":
        output = export_sarif(
            chains=chains, audit_results=audit_results or {},
            shadowing_findings=shadowing_findings,
            filepath=args.file,
        )
    else:
        output = export_audit_json(
            chains=chains, shadowing_findings=shadowing_findings,
            filepath=args.file,
        )

    write_export(output, args.output)
    print(f"[INFO] Written to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
