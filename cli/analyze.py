#!/usr/bin/env python3
"""Analyze one canonical policy JSON file."""

import argparse
import json
import sys
from pathlib import Path

from firewall_analyzer.analyzer import run_audit
from firewall_analyzer.policy_graph import PolicyGraph
from firewall_analyzer.reporting import write_text_report


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze canonical firewall JSON")
    parser.add_argument("file", help="Canonical policy JSON file")
    parser.add_argument("--output", required=True, help="Analysis result JSON file")
    parser.add_argument(
        "--admin-cidr",
        nargs="+",
        default=None,
        help="Trusted administrator network(s)",
    )
    parser.add_argument(
        "--all-zones",
        action="store_true",
        help="Include inactive firewalld zones in the audit",
    )
    args = parser.parse_args()

    try:
        with open(args.file, encoding="utf-8") as source:
            graph = PolicyGraph.from_json(source.read())
        audit = run_audit(
            graph,
            admin_cidrs=args.admin_cidr,
            active_only=False if args.all_zones else None,
        )
        result = {
            "schema_version": "1.0",
            "source_file": graph.metadata.get("source_file", args.file),
            "source_format": graph.source_format,
            "status": "FAIL" if audit.has_failures() else "PASS",
            "findings": audit.to_dict(),
        }
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as output:
            json.dump(result, output, indent=2)
            output.write("\n")
        report_path = Path(args.output).with_suffix(".result.txt")
        write_text_report(report_path, result)
    except Exception as error:
        print(f"[ERROR] Analysis failed: {error}", file=sys.stderr)
        raise SystemExit(2)

    print(f"[INFO] Analyzed {args.file} -> {args.output}")
    print(f"[INFO] Report written to {report_path}")
    raise SystemExit(1 if result["status"] == "FAIL" else 0)


if __name__ == "__main__":
    main()
