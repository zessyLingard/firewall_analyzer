#!/usr/bin/env python3
"""Convert one native firewall file into canonical JSON."""

import argparse
import sys

from firewall_analyzer.parsers import load_rules


def main() -> None:
    parser = argparse.ArgumentParser(description="Parse firewall input into canonical JSON")
    parser.add_argument("file", help="Native firewall ruleset file")
    parser.add_argument(
        "--format",
        choices=["auto", "iptables", "nftables", "firewalld", "ufw"],
        default="auto",
    )
    parser.add_argument("--output", required=True, help="Canonical JSON output file")
    args = parser.parse_args()

    try:
        graph = load_rules(args.file, format=args.format)
        graph.metadata["source_file"] = args.file
        with open(args.output, "w", encoding="utf-8") as output:
            output.write(graph.to_json())
    except Exception as error:
        print(f"[ERROR] Parse failed: {error}", file=sys.stderr)
        raise SystemExit(2)

    print(f"[INFO] Parsed {args.file} -> {args.output}")


if __name__ == "__main__":
    main()
